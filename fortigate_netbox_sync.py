#!/usr/bin/env python3
"""
fortigate-netbox-sync
=====================
Synchronize a FortiGate firewall into NetBox (DCIM + IPAM).

Objects created/updated:
  - Device (the FortiGate itself)
  - Physical interfaces  -> dcim.interfaces
  - VLAN interfaces      -> dcim.interfaces + ipam.vlans
  - IP addresses         -> ipam.ip_addresses
  - Prefixes             -> ipam.prefixes
  - IPsec tunnels        -> vpn.tunnels + vpn.tunnel_terminations
  - SSL-VPN tunnel       -> vpn.tunnels
  - SSL-VPN IP pools     -> ipam.ip_ranges

Usage:
  python3 fortigate_netbox_sync.py --config config.yaml
  python3 fortigate_netbox_sync.py --config config.yaml --dry-run

Author : ONCOGARD / Pierre — released under MIT license
Repo   : https://github.com/Grujowmi/fortigate-netbox-sync
"""

import argparse
import ipaddress
import logging
import sys
from typing import Optional

import pynetbox
import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("fgt-nb-sync")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_TAG_NAME  = "Source: fortigate-sync"
SOURCE_TAG_COLOR = "f06000"   # Fortinet orange
SYNCED_TAG_NAME  = "netbox-synced"
SYNCED_TAG_COLOR = "00add8"

FORTIGATE_ROLE_SLUG  = "firewall"
FORTIGATE_ROLE_NAME  = "Firewall"
FORTIGATE_ROLE_COLOR = "aa1409"

MANUFACTURER_NAME = "Fortinet"
MANUFACTURER_SLUG = "fortinet"

# Mapping FortiGate interface type -> NetBox interface type
IFACE_TYPE_MAP = {
    "physical"   : "1000base-t",  # refined later based on speed
    "vlan"       : "virtual",
    "aggregate"  : "lag",
    "loopback"   : "virtual",
    "tunnel"     : "virtual",
    "redundant"  : "lag",
    "hard-switch": "virtual",
    "vap-switch" : "virtual",
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def slugify(name: str) -> str:
    """Convert a name into a NetBox-compatible slug."""
    import re
    s = name.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_-]+", "-", s)
    s = re.sub(r"^-+|-+$", "", s)
    return s[:50]


def is_permitted(ip_str: str, permitted: list[str]) -> bool:
    """Return True if the IP belongs to at least one of the permitted subnets."""
    if not permitted:
        return True
    try:
        ip = ipaddress.ip_address(ip_str.split("/")[0])
        return any(ip in ipaddress.ip_network(n, strict=False) for n in permitted)
    except ValueError:
        return False


def cidr_from_fortigate(ip: str, mask: str = "") -> Optional[str]:
    """
    Convert a FortiGate IP field to CIDR notation.

    Handles two formats:
      - Combined : ip="172.17.1.254 255.255.255.0", mask=""  (FortiOS 7.x)
      - Separate : ip="172.17.1.254", mask="255.255.255.0"   (older firmware)

    Returns None if invalid or 0.0.0.0.
    """
    if not ip:
        return None
    # Combined format: "x.x.x.x y.y.y.y"
    if " " in ip:
        parts = ip.split()
        if len(parts) == 2:
            ip, mask = parts[0], parts[1]
        else:
            return None
    if not ip or ip == "0.0.0.0":
        return None
    if not mask or mask == "0.0.0.0":
        return None
    try:
        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
        return f"{ip}/{prefix_len}"
    except ValueError:
        return None


def network_from_cidr(cidr: str) -> str:
    """Return the network prefix from a CIDR address (e.g. 172.17.1.254/24 -> 172.17.1.0/24)."""
    return str(ipaddress.ip_interface(cidr).network)


# ---------------------------------------------------------------------------
# FortiGate REST client
# ---------------------------------------------------------------------------

class FortiGateClient:
    """Minimal read-only FortiGate REST API client."""

    def __init__(self, host: str, token: str, validate_ssl: bool = False):
        self.base = f"https://{host}"
        self.session = requests.Session()
        self.session.verify = validate_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type" : "application/json",
        })

    def _get(self, path: str, params: dict = None) -> list:
        url = f"{self.base}/api/v2/{path}"
        resp = self.session.get(url, params=params or {})
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", data) if isinstance(data, dict) else data

    def get_system_status(self) -> dict:
        """Return system status (model, serial number, OS version).

        FortiGate spreads data across two levels:
          - root level: serial, version, build
          - results level: model_name, model_number, model, hostname
        We merge both so callers get a flat dict.
        """
        resp = self.session.get(f"{self.base}/api/v2/monitor/system/status")
        resp.raise_for_status()
        raw = resp.json()
        log.debug(f"  [DEBUG] system/status raw: {raw}")
        # Merge root-level keys with results sub-dict
        merged = {**raw, **raw.get("results", {})}
        return merged

    def get_interfaces(self) -> list:
        """Return all interfaces."""
        return self._get("cmdb/system/interface")

    def get_vlans(self) -> list:
        """Return only VLAN interfaces."""
        return [i for i in self.get_interfaces() if i.get("type") == "vlan"]

    def get_physical_interfaces(self) -> list:
        """Return only physical/aggregate/redundant interfaces."""
        return [i for i in self.get_interfaces()
                if i.get("type") in ("physical", "aggregate", "redundant")]

    def get_ipsec_tunnels(self) -> list:
        """Return all IPsec phase1 tunnel definitions."""
        return self._get("cmdb/vpn.ipsec/phase1-interface")

    def get_ssl_vpn_settings(self) -> dict:
        """Return SSL-VPN global settings."""
        raw = self._get("cmdb/vpn.ssl/settings")
        # _get returns results value; for ssl settings it's a dict not a list
        return raw if isinstance(raw, dict) else {}

    def get_ip_pools(self) -> list:
        """Return firewall address objects of type iprange.

        SSL-VPN tunnel pools (e.g. SSLVPN_TUNNEL_ADDR1) are stored as
        firewall/address with type=iprange, not in firewall/ippool.
        """
        all_addr = self._get("cmdb/firewall/address")
        return [a for a in all_addr if a.get("type") == "iprange"]


# ---------------------------------------------------------------------------
# NetBox sync engine
# ---------------------------------------------------------------------------

class NetBoxSync:

    def __init__(self, config: dict, dry_run: bool = False):
        self.dry_run   = dry_run
        self.cfg       = config
        self.nb_cfg    = config["netbox"]
        self.fgt_cfg   = config["fortigate"]
        self.opts      = config.get("options", {})
        self.permitted = self.opts.get("permitted_subnets", [])
        self.site_name = self.nb_cfg.get("site", "")

        # Initialize pynetbox
        self.nb = pynetbox.api(
            self.nb_cfg["host"],
            token=self.nb_cfg["token"],
        )
        if not self.nb_cfg.get("validate_ssl", True):
            import requests as req
            s = req.Session()
            s.verify = False
            self.nb.http_session = s

        # Initialize FortiGate client
        self.fgt = FortiGateClient(
            host         = self.fgt_cfg["host"],
            token        = self.fgt_cfg["token"],
            validate_ssl = self.fgt_cfg.get("validate_ssl", False),
        )

        # Internal cache
        self._site   = None
        self._device = None
        self._tags   = {}

    # ------------------------------------------------------------------
    # NetBox utilities
    # ------------------------------------------------------------------

    def _dry(self, action: str, obj_type: str, name: str, data: dict = None):
        """Log a dry-run action without writing to NetBox."""
        extras = f" | {data}" if data else ""
        log.info(f"[DRY-RUN] {action} {obj_type}: {name}{extras}")

    def _get_or_create_tag(self, name: str, color: str) -> object:
        """Return an existing tag or create it.

        Uses an internal cache to avoid repeated API calls.
        In dry-run mode the sentinel value False is stored so we only
        log the CREATE once and never query again.
        Handles slug collisions gracefully by falling back to a GET on error.
        """
        if name in self._tags:
            return self._tags[name] or None  # False sentinel -> None

        # Try by name first, then by slug (netbox-sync may have created it already)
        tag = self.nb.extras.tags.get(name=name)
        if not tag:
            tag = self.nb.extras.tags.get(slug=slugify(name))
        if not tag:
            if self.dry_run:
                self._dry("CREATE", "Tag", name)
                self._tags[name] = False  # sentinel: logged, skip next calls
                return None
            try:
                tag = self.nb.extras.tags.create({"name": name, "slug": slugify(name), "color": color})
                log.info(f"  + Tag created: {name}")
            except Exception:
                # Slug collision: another tag with same slug exists, fetch it
                tag = self.nb.extras.tags.get(slug=slugify(name))
                if tag:
                    log.debug(f"  ~ Tag already exists (slug collision): {name}")
                else:
                    raise
        self._tags[name] = tag
        return tag

    def _tags_ids(self) -> list:
        """Return the IDs of the two sync tags."""
        t1 = self._get_or_create_tag(SOURCE_TAG_NAME, SOURCE_TAG_COLOR)
        t2 = self._get_or_create_tag(SYNCED_TAG_NAME, SYNCED_TAG_COLOR)
        ids = []
        if t1: ids.append(t1.id)
        if t2: ids.append(t2.id)
        return ids

    def _get_or_create_manufacturer(self) -> object:
        """Return the Fortinet manufacturer object, creating it if needed."""
        m = self.nb.dcim.manufacturers.get(slug=MANUFACTURER_SLUG)
        if not m:
            if self.dry_run:
                self._dry("CREATE", "Manufacturer", MANUFACTURER_NAME)
                return None
            m = self.nb.dcim.manufacturers.create({
                "name": MANUFACTURER_NAME,
                "slug": MANUFACTURER_SLUG,
            })
            log.info(f"  + Manufacturer created: {MANUFACTURER_NAME}")
        return m

    def _get_or_create_device_type(self, model: str, manufacturer_id: int) -> object:
        """Return a device type object, creating it if needed."""
        slug = slugify(model)
        dt = self.nb.dcim.device_types.get(slug=slug)
        if not dt:
            if self.dry_run:
                self._dry("CREATE", "DeviceType", model)
                return None
            dt = self.nb.dcim.device_types.create({
                "manufacturer": manufacturer_id,
                "model"       : model,
                "slug"        : slug,
            })
            log.info(f"  + Device type created: {model}")
        return dt

    def _get_or_create_device_role(self) -> object:
        """Return the Firewall device role, creating it if needed."""
        role = self.nb.dcim.device_roles.get(slug=FORTIGATE_ROLE_SLUG)
        if not role:
            if self.dry_run:
                self._dry("CREATE", "DeviceRole", FORTIGATE_ROLE_NAME)
                return None
            role = self.nb.dcim.device_roles.create({
                "name" : FORTIGATE_ROLE_NAME,
                "slug" : FORTIGATE_ROLE_SLUG,
                "color": FORTIGATE_ROLE_COLOR,
            })
            log.info(f"  + Device role created: {FORTIGATE_ROLE_NAME}")
        return role

    def _get_site(self) -> object:
        """Return the configured site object. Raises if not found."""
        if self._site:
            return self._site
        site = self.nb.dcim.sites.get(name=self.site_name)
        if not site:
            raise ValueError(f"Site '{self.site_name}' not found in NetBox. Please create it first.")
        self._site = site
        return site

    # ------------------------------------------------------------------
    # Step 1: FortiGate device
    # ------------------------------------------------------------------

    def sync_device(self) -> object:
        log.info("--- Step 1: FortiGate device")
        status = self.fgt.get_system_status()

        serial  = status.get("serial", "UNKNOWN")
        # Build a proper model name: "FortiGate-100F" from model_name + model_number
        model_name   = status.get("model_name", "FortiGate")
        model_number = status.get("model_number", "")
        model        = f"{model_name}-{model_number}" if model_number else model_name
        version      = status.get("version", "")

        log.info(f"  FortiGate detected: {model} | S/N: {serial} | OS: {version}")

        site         = self._get_site()
        manufacturer = self._get_or_create_manufacturer()
        device_type  = self._get_or_create_device_type(model, manufacturer.id if manufacturer else 0)
        device_role  = self._get_or_create_device_role()

        # Look up by serial first, then by name
        device_name = self.fgt_cfg.get("device_name", model)
        device = self.nb.dcim.devices.get(serial=serial)
        if not device:
            device = self.nb.dcim.devices.get(name=device_name, site_id=site.id)

        payload = {
            "name"       : device_name,
            "device_type": device_type.id if device_type else 0,
            "role"       : device_role.id if device_role else 0,
            "site"       : site.id,
            "serial"     : serial,
            "status"     : "active",
            "tags"       : self._tags_ids(),
            "comments"   : f"FortiOS {version}",
        }

        if not device:
            if self.dry_run:
                self._dry("CREATE", "Device", device_name, {"serial": serial, "model": model})
                return None
            device = self.nb.dcim.devices.create(payload)
            log.info(f"  + Device created: {device_name}")
        else:
            if self.dry_run:
                self._dry("UPDATE", "Device", device_name)
            else:
                device.update(payload)
                log.info(f"  ~ Device updated: {device_name}")

        self._device = device
        return device

    # ------------------------------------------------------------------
    # Step 2: Physical interfaces
    # ------------------------------------------------------------------

    def sync_physical_interfaces(self):
        log.info("--- Step 2: Physical interfaces")
        if not self._device and not self.dry_run:
            log.warning("  Device not set, skipping.")
            return

        device_id = self._device.id if self._device else 0
        physical  = self.fgt.get_physical_interfaces()
        log.info(f"  {len(physical)} physical interfaces found on FortiGate")

        for iface in physical:
            name = iface.get("name", "")
            if not name:
                continue

            itype   = IFACE_TYPE_MAP.get(iface.get("type", "physical"), "other")
            desc    = iface.get("alias", iface.get("description", ""))
            try:
                speed = int(iface.get("speed", 0) or 0)
            except (ValueError, TypeError):
                speed = 0  # FortiGate may return "auto" or other non-numeric strings
            mac     = iface.get("macaddr", "")
            enabled = iface.get("status", "up") == "up"

            # Refine interface type based on reported speed
            if itype == "1000base-t" and speed:
                if   speed >= 100000: itype = "100gbase-x-qsfp28"
                elif speed >= 40000 : itype = "40gbase-x-qsfpp"
                elif speed >= 25000 : itype = "25gbase-x-sfp28"
                elif speed >= 10000 : itype = "10gbase-x-sfpp"
                elif speed >= 1000  : itype = "1000base-t"
                elif speed >= 100   : itype = "100base-tx"

            payload = {
                "device"     : device_id,
                "name"       : name,
                "type"       : itype,
                "enabled"    : enabled,
                "description": desc[:200] if desc else "",
                "mac_address": mac.upper() if mac else None,
                "tags"       : self._tags_ids(),
            }

            existing = self.nb.dcim.interfaces.get(device_id=device_id, name=name) if not self.dry_run else None

            if not existing:
                if self.dry_run:
                    self._dry("CREATE", "Interface", f"{name} (physical)")
                else:
                    self.nb.dcim.interfaces.create(payload)
                    log.info(f"  + Interface created: {name}")
            else:
                if self.dry_run:
                    self._dry("UPDATE", "Interface", name)
                else:
                    existing.update(payload)
                    log.debug(f"  ~ Interface updated: {name}")

    # ------------------------------------------------------------------
    # Step 3: VLANs + VLAN interfaces
    # ------------------------------------------------------------------

    def sync_vlans(self):
        log.info("--- Step 3: VLANs + VLAN interfaces")
        if not self._device and not self.dry_run:
            log.warning("  Device not set, skipping.")
            return

        site      = self._get_site()
        device_id = self._device.id if self._device else 0
        vlans     = self.fgt.get_vlans()
        log.info(f"  {len(vlans)} VLAN interfaces found on FortiGate")

        for vlan in vlans:
            name    = vlan.get("name", "")
            vlan_id = vlan.get("vlanid", 0)
            if not name or not vlan_id:
                continue

            alias   = vlan.get("alias", "").strip()
            desc    = alias or vlan.get("description", "")
            enabled = vlan.get("status", "up") == "up"
            parent  = vlan.get("interface", "")
            # Use alias as VLAN name if set (e.g. "IT"), otherwise use interface name (e.g. "vlan96")
            vlan_name = alias if alias else name

            # --- VLAN in ipam.vlans ---
            nb_vlan = self.nb.ipam.vlans.get(vid=vlan_id, site_id=site.id) if not self.dry_run else None
            vlan_payload = {
                "site"  : site.id,
                "vid"   : vlan_id,
                "name"  : vlan_name,
                "status": "active",
                "tags"  : self._tags_ids(),
            }
            if not nb_vlan:
                if self.dry_run:
                    self._dry("CREATE", "VLAN", f"{name} (id={vlan_id})")
                else:
                    nb_vlan = self.nb.ipam.vlans.create(vlan_payload)
                    log.info(f"  + VLAN created: {name} (id={vlan_id})")
            else:
                if self.dry_run:
                    self._dry("UPDATE", "VLAN", f"{name} (id={vlan_id})")
                else:
                    nb_vlan.update(vlan_payload)
                    log.debug(f"  ~ VLAN updated: {name} (id={vlan_id})")

            # --- VLAN interface in dcim.interfaces ---
            iface_payload = {
                "device"       : device_id,
                "name"         : name,
                "type"         : "virtual",
                "enabled"      : enabled,
                "description"  : desc[:200] if desc else "",
                "mode"         : "access",
                "untagged_vlan": nb_vlan.id if nb_vlan else None,
                "tags"         : self._tags_ids(),
            }
            # Link to parent physical interface if it exists
            if parent and not self.dry_run:
                parent_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=parent)
                if parent_iface:
                    iface_payload["parent"] = parent_iface.id

            existing_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=name) if not self.dry_run else None
            if not existing_iface:
                if self.dry_run:
                    self._dry("CREATE", "VLAN Interface", name)
                    nb_iface = None
                else:
                    nb_iface = self.nb.dcim.interfaces.create(iface_payload)
                    log.info(f"  + VLAN interface created: {name}")
            else:
                if self.dry_run:
                    self._dry("UPDATE", "VLAN Interface", name)
                    nb_iface = None
                else:
                    existing_iface.update(iface_payload)
                    nb_iface = existing_iface
                    log.debug(f"  ~ VLAN interface updated: {name}")

            # --- IP address on the VLAN interface ---
            # FortiOS 7.x returns "x.x.x.x y.y.y.y" in a single "ip" field
            ip_str   = vlan.get("ip", "")
            mask_str = vlan.get("netmask", "")  # may be empty on newer firmware
            if ip_str:
                self._sync_ip(ip_str, mask_str, nb_iface, nb_vlan, site)

    # ------------------------------------------------------------------
    # Step 4: IP addresses (called by sync_vlans and sync_physical_ips)
    # ------------------------------------------------------------------

    def _sync_ip(self, ip_str: str, mask_str: str, nb_iface, nb_vlan, site):
        """Create or update an IP address and its parent prefix in NetBox."""
        cidr = cidr_from_fortigate(ip_str, mask_str)
        if not cidr:
            return
        if not is_permitted(cidr, self.permitted):
            log.debug(f"    IP {cidr} outside permitted_subnets, skipped")
            return

        network = network_from_cidr(cidr)

        # Prefix
        # Search by prefix value only (site-aware search can miss global-table duplicates)
        prefix = None
        if not self.dry_run:
            results = list(self.nb.ipam.prefixes.filter(prefix=network))
            if results:
                # Prefer the one matching our site; otherwise take the first
                site_match = [p for p in results if getattr(getattr(p, "site", None), "id", None) == site.id]
                prefix = site_match[0] if site_match else results[0]

        prefix_payload = {
            "prefix": network,
            "site"  : site.id,
            "status": "active",
            "tags"  : self._tags_ids(),
        }
        if nb_vlan and not self.dry_run:
            prefix_payload["vlan"] = nb_vlan.id

        if not prefix:
            if self.dry_run:
                self._dry("CREATE", "Prefix", network)
            else:
                self.nb.ipam.prefixes.create(prefix_payload)
                log.info(f"    + Prefix created: {network}")
        else:
            if not self.dry_run:
                prefix.update(prefix_payload)
                log.debug(f"    ~ Prefix updated: {network}")

        # Create usable IP range for the prefix (first+1 to last-1)
        # e.g. 172.17.1.0/24 -> 172.17.1.1 - 172.17.1.254
        try:
            net_obj   = ipaddress.ip_network(network, strict=False)
            all_hosts = list(net_obj.hosts())  # excludes network + broadcast
            if len(all_hosts) >= 2:
                range_start = str(all_hosts[0])
                range_end   = str(all_hosts[-1])
                range_desc  = f"Usable range for {network}"

                range_payload = {
                    "start_address": range_start,
                    "end_address"  : range_end,
                    "site"         : site.id,
                    "status"       : "active",
                    "description"  : range_desc,
                    "tags"         : self._tags_ids(),
                }

                existing_range = None
                if not self.dry_run:
                    results = list(self.nb.ipam.ip_ranges.filter(
                        start_address=range_start,
                        end_address=range_end,
                    ))
                    if results:
                        existing_range = results[0]

                if not existing_range:
                    if self.dry_run:
                        self._dry("CREATE", "IP Range", f"{range_start} - {range_end}")
                    else:
                        self.nb.ipam.ip_ranges.create(range_payload)
                        log.info(f"    + IP range created: {range_start} - {range_end}")
                else:
                    if not self.dry_run:
                        existing_range.update(range_payload)
                        log.debug(f"    ~ IP range updated: {range_start} - {range_end}")
        except Exception as e:
            log.warning(f"    Could not create IP range for {network}: {e}")

        # IP address
        existing_ip = self.nb.ipam.ip_addresses.get(address=cidr) if not self.dry_run else None
        ip_payload = {
            "address": cidr,
            "status" : "active",
            "tags"   : self._tags_ids(),
        }
        if nb_iface and not self.dry_run:
            ip_payload["assigned_object_type"] = "dcim.interface"
            ip_payload["assigned_object_id"]   = nb_iface.id

        if not existing_ip:
            if self.dry_run:
                self._dry("CREATE", "IP Address", cidr)
            else:
                self.nb.ipam.ip_addresses.create(ip_payload)
                log.info(f"    + IP address created: {cidr}")
        else:
            if self.dry_run:
                self._dry("UPDATE", "IP Address", cidr)
            else:
                existing_ip.update(ip_payload)
                log.debug(f"    ~ IP address updated: {cidr}")

    # ------------------------------------------------------------------
    # Step 5: IPs on physical interfaces
    # ------------------------------------------------------------------

    def sync_physical_ips(self):
        log.info("--- Step 5: IPs on physical interfaces")
        if not self._device and not self.dry_run:
            return

        site      = self._get_site()
        device_id = self._device.id if self._device else 0
        physical  = self.fgt.get_physical_interfaces()

        for iface in physical:
            ip_str   = iface.get("ip", "")
            mask_str = iface.get("netmask", "")  # may be empty on newer firmware
            name     = iface.get("name", "")
            if not ip_str:
                continue
            nb_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=name) if not self.dry_run else None
            self._sync_ip(ip_str, mask_str, nb_iface, None, site)

    # ------------------------------------------------------------------
    # Step 6: VPN tunnels (IPsec + SSL-VPN)
    # ------------------------------------------------------------------

    def sync_vpn(self):
        log.info("--- Step 6: VPN tunnels")
        if not self._device and not self.dry_run:
            log.warning("  Device not set, skipping.")
            return

        self._sync_ipsec_tunnels()
        self._sync_ssl_vpn()

    def _get_or_create_ike_proposal(self, name: str) -> object:
        """Return an IKE proposal object, creating it if needed."""
        prop = self.nb.vpn.ike_proposals.get(name=name)
        if not prop:
            if self.dry_run:
                self._dry("CREATE", "IKE Proposal", name)
                return None
            prop = self.nb.vpn.ike_proposals.create({
                "name"            : name,
                "encryption_algorithm": "aes-256",
                "authentication_algorithm": "sha256",
                "group"           : "14",
            })
            log.info(f"  + IKE Proposal created: {name}")
        return prop

    def _get_or_create_ipsec_proposal(self, name: str) -> object:
        """Return an IPsec proposal object, creating it if needed."""
        prop = self.nb.vpn.ipsec_proposals.get(name=name)
        if not prop:
            if self.dry_run:
                self._dry("CREATE", "IPsec Proposal", name)
                return None
            prop = self.nb.vpn.ipsec_proposals.create({
                "name"                   : name,
                "encryption_algorithm"   : "aes-256",
                "authentication_algorithm": "sha256",
            })
            log.info(f"  + IPsec Proposal created: {name}")
        return prop

    def _sync_ipsec_tunnels(self):
        """Sync IPsec phase1 tunnels into NetBox vpn.tunnels."""
        tunnels = self.fgt.get_ipsec_tunnels()
        log.info(f"  {len(tunnels)} IPsec tunnels found on FortiGate")

        device_id = self._device.id if self._device else 0

        for t in tunnels:
            name       = t.get("name", "")
            remote_gw  = t.get("remote-gw", "")
            local_iface = t.get("interface", "")
            ike_ver    = t.get("ike-version", "2")
            authmethod = t.get("authmethod", "psk")
            keylife    = t.get("keylife", 86400)

            if not name:
                continue

            # Build comment with relevant info
            comments = (
                f"IKEv{ike_ver} | Auth: {authmethod} | "
                f"Keylife: {keylife}s | Local interface: {local_iface}"
            )

            # Tunnel name for IKE/IPsec proposals (slugified)
            proposal_name = f"FGT-IKEv{ike_ver}-{slugify(name)}"[:64]

            tunnel_payload = {
                "name"       : name,
                "status"     : "active",
                "encapsulation": "ipsec-tunnel",
                "ipsec_profile": None,
                "tunnel_id"  : None,
                "tags"       : self._tags_ids(),
                "comments"   : comments,
            }

            existing = self.nb.vpn.tunnels.get(name=name) if not self.dry_run else None

            if not existing:
                if self.dry_run:
                    self._dry("CREATE", "IPsec Tunnel", name,
                              {"remote_gw": remote_gw, "interface": local_iface})
                    continue
                tunnel = self.nb.vpn.tunnels.create(tunnel_payload)
                log.info(f"  + IPsec tunnel created: {name}")
            else:
                if self.dry_run:
                    self._dry("UPDATE", "IPsec Tunnel", name)
                    continue
                existing.update(tunnel_payload)
                tunnel = existing
                log.debug(f"  ~ IPsec tunnel updated: {name}")

            # Termination A — local side (FortiGate device interface)
            self._sync_tunnel_termination(
                tunnel    = tunnel,
                role      = "peer",
                term_side = "a",
                obj_type  = "dcim.interface",
                device_id = device_id,
                iface_name= local_iface,
                ip_address= None,
            )

            # Termination B — remote peer
            if remote_gw and remote_gw != "0.0.0.0":
                self._sync_tunnel_termination(
                    tunnel    = tunnel,
                    role      = "peer",
                    term_side = "b",
                    obj_type  = None,
                    device_id = None,
                    iface_name= None,
                    ip_address= remote_gw,
                )

    def _sync_tunnel_termination(self, tunnel, role: str, term_side: str,
                                  obj_type, device_id, iface_name, ip_address):
        """Create or skip a tunnel termination (side A or B)."""
        if self.dry_run:
            label = iface_name or ip_address or "?"
            self._dry("CREATE", f"Tunnel Termination ({term_side})", label)
            return

        # Check if termination already exists for this tunnel+role+side
        existing = list(self.nb.vpn.tunnel_terminations.filter(
            tunnel_id=tunnel.id,
        ))

        # For simplicity: if any termination exists for this tunnel, skip
        if existing:
            log.debug(f"    Terminations already exist for tunnel '{tunnel.name}', skipping")
            return

        payload = {
            "tunnel": tunnel.id,
            "role"  : "peer",
            "tags"  : self._tags_ids(),
        }

        # Side A: link to local device interface
        if obj_type == "dcim.interface" and device_id and iface_name:
            nb_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=iface_name)
            if nb_iface:
                payload["termination_type"] = "dcim.interface"
                payload["termination_id"]   = nb_iface.id

        # Side B: store remote IP as outside IP
        if ip_address:
            payload["outside_ip_address"] = ip_address

        try:
            self.nb.vpn.tunnel_terminations.create(payload)
            log.debug(f"    + Termination created for tunnel '{tunnel.name}'")
        except Exception as e:
            # Interface already used by another tunnel (NetBox limitation: 1 interface = 1 tunnel)
            # Fall back: add local interface name to tunnel comments for documentation
            if "already attached" in str(e) or "termination_type" in str(e):
                if iface_name:
                    try:
                        existing_tunnel = self.nb.vpn.tunnels.get(name=tunnel.name)
                        if existing_tunnel:
                            old_comments = existing_tunnel.comments or ""
                            note = f"Local interface: {iface_name} (shared WAN — NetBox only allows one tunnel per interface)"
                            if note not in old_comments:
                                new_comments = "\n".join(filter(None, [old_comments, note]))
                                existing_tunnel.update({"comments": new_comments})
                            log.debug(f"    ~ Added local interface to comments for '{tunnel.name}'")
                    except Exception:
                        pass
            else:
                log.warning(f"    Could not create termination for '{tunnel.name}': {e}")

    def _sync_ssl_vpn(self):
        """Sync SSL-VPN as a single tunnel + IP range in NetBox."""
        settings = self.fgt.get_ssl_vpn_settings()
        if not settings or settings.get("status") != "enable":
            log.info("  SSL-VPN disabled or not found, skipping.")
            return

        log.info("  SSL-VPN enabled, syncing...")

        tunnel_name = "SSL-VPN"
        cert        = settings.get("servercert", "")
        auth_timeout = settings.get("auth-timeout", 0)
        comments    = f"Certificate: {cert} | Auth timeout: {auth_timeout}s"

        tunnel_payload = {
            "name"         : tunnel_name,
            "status"       : "active",
            "encapsulation": "openvpn",
            "tags"         : self._tags_ids(),
            "comments"     : comments,
        }

        existing = self.nb.vpn.tunnels.get(name=tunnel_name) if not self.dry_run else None
        if not existing:
            if self.dry_run:
                self._dry("CREATE", "SSL-VPN Tunnel", tunnel_name)
            else:
                self.nb.vpn.tunnels.create(tunnel_payload)
                log.info(f"  + SSL-VPN tunnel created: {tunnel_name}")
        else:
            if self.dry_run:
                self._dry("UPDATE", "SSL-VPN Tunnel", tunnel_name)
            else:
                existing.update(tunnel_payload)
                log.debug(f"  ~ SSL-VPN tunnel updated: {tunnel_name}")

        # Sync SSL-VPN IP pools as NetBox IP ranges
        pool_names = [p.get("name") for p in settings.get("tunnel-ip-pools", [])]
        if not pool_names:
            return

        all_pools = self.fgt.get_ip_pools()
        site = self._get_site()

        for pool in all_pools:
            if pool.get("name") not in pool_names:
                continue

            start_ip = pool.get("start-ip", pool.get("startip", ""))
            end_ip   = pool.get("end-ip", pool.get("endip", ""))
            if not start_ip or not end_ip or start_ip == "0.0.0.0":
                continue

            range_payload = {
                "start_address": start_ip,
                "end_address"  : end_ip,
                "site"         : site.id,
                "status"       : "active",
                "description"  : f"SSL-VPN pool: {pool.get('name')}",
                "tags"         : self._tags_ids(),
            }

            existing_range = self.nb.ipam.ip_ranges.filter(
                start_address=start_ip,
                end_address=end_ip,
            )
            existing_range = list(existing_range)

            if not existing_range:
                if self.dry_run:
                    self._dry("CREATE", "IP Range (SSL-VPN pool)",
                              f"{start_ip} - {end_ip}")
                else:
                    self.nb.ipam.ip_ranges.create(range_payload)
                    log.info(f"  + SSL-VPN IP range created: {start_ip} - {end_ip}")
            else:
                if self.dry_run:
                    self._dry("UPDATE", "IP Range (SSL-VPN pool)",
                              f"{start_ip} - {end_ip}")
                else:
                    existing_range[0].update(range_payload)
                    log.debug(f"  ~ SSL-VPN IP range updated: {start_ip} - {end_ip}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self):
        mode = "[DRY-RUN] " if self.dry_run else ""
        log.info(f"{'='*60}")
        log.info(f" {mode}FortiGate -> NetBox Sync")
        log.info(f" FortiGate : {self.fgt_cfg['host']}")
        log.info(f" NetBox    : {self.nb_cfg['host']}")
        log.info(f" Site      : {self.site_name}")
        log.info(f"{'='*60}")

        try:
            self.sync_device()
            self.sync_physical_interfaces()
            self.sync_vlans()
            self.sync_physical_ips()
            self.sync_vpn()
        except Exception as e:
            log.error(f"Fatal error: {e}")
            raise

        log.info("--- Sync completed successfully")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load and validate the YAML configuration file."""
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    required = [
        ("fortigate", "host"),
        ("fortigate", "token"),
        ("netbox",    "host"),
        ("netbox",    "token"),
        ("netbox",    "site"),
    ]
    for section, key in required:
        if not cfg.get(section, {}).get(key):
            raise ValueError(f"config.yaml: '{section}.{key}' is required")
    return cfg


def main():
    parser = argparse.ArgumentParser(
        description="Synchronize a FortiGate firewall into NetBox (DCIM + IPAM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fortigate_netbox_sync.py --config config.yaml --dry-run
  python3 fortigate_netbox_sync.py --config config.yaml
  python3 fortigate_netbox_sync.py --config config.yaml --debug
        """,
    )
    parser.add_argument("--config",  "-c", required=True, help="Path to config.yaml")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Simulate without writing to NetBox")
    parser.add_argument("--debug",   "-d", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        log.error(f"Configuration error: {e}")
        sys.exit(1)

    sync = NetBoxSync(config=config, dry_run=args.dry_run)
    sync.run()


if __name__ == "__main__":
    main()