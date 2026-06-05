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

Usage:
  python3 fortigate_netbox_sync.py --config config.yaml
  python3 fortigate_netbox_sync.py --config config.yaml --dry-run

Author : Grujowmi — released under MIT license
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


def cidr_from_fortigate(ip: str, mask: str) -> Optional[str]:
    """
    Convert a FortiGate ip + netmask pair (e.g. "172.17.1.254", "255.255.255.0")
    to CIDR notation (e.g. "172.17.1.254/24").
    Returns None if invalid or 0.0.0.0.
    """
    if not ip or ip == "0.0.0.0":
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
            ip_str   = vlan.get("ip", "")
            mask_str = vlan.get("netmask", "")
            if ip_str and mask_str:
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
        prefix = self.nb.ipam.prefixes.get(prefix=network, site_id=site.id) if not self.dry_run else None
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
            mask_str = iface.get("netmask", "")
            name     = iface.get("name", "")
            if not ip_str or not mask_str or ip_str == "0.0.0.0":
                continue
            nb_iface = self.nb.dcim.interfaces.get(device_id=device_id, name=name) if not self.dry_run else None
            self._sync_ip(ip_str, mask_str, nb_iface, None, site)

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
