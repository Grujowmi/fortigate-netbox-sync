# fortigate-netbox-sync

> 🇬🇧 English | [🇫🇷 Français](#français)

---

## English

Python script to synchronize a FortiGate firewall into NetBox (DCIM + IPAM).

### Tested on

| Device | FortiOS |
|---|---|
| FortiGate 100F | v7.4.12 |

### What gets synchronized

| Source (FortiGate) | Destination (NetBox) |
|---|---|
| Model + serial number | `dcim.devices` |
| Physical interfaces | `dcim.interfaces` |
| VLAN interfaces (name + ID) | `dcim.interfaces` + `ipam.vlans` |
| Interface IP addresses | `ipam.ip_addresses` |
| Network prefixes | `ipam.prefixes` |

All created objects are tagged `Source: fortigate-sync` + `netbox-synced` for traceability.
The script is **idempotent**: running it multiple times does not create duplicates — existing objects are updated.

### Requirements

- Python ≥ 3.10
- NetBox ≥ 4.0 (tested on 4.6.x)
- Read-only REST API account on the FortiGate

### Installation

```bash
git clone https://github.com/Grujowmi/fortigate-netbox-sync.git
cd fortigate-netbox-sync
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### FortiGate API account

Create a read-only REST API account on your FortiGate:

**System → Administrators → Create New → REST API Admin**
- Profile: `read-only`
- Trusted hosts: IP address of your NetBox server (e.g. `172.17.1.207/32`)
- Check **"Don't filter VDOM traffic"** if you use VDOMs

Copy the generated token into your `config.yaml`.

### Configuration

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Fill in your values:

```yaml
fortigate:
  host: 10.0.0.1                   # FortiGate IP or FQDN (active node in HA)
  token: YOUR_FORTIGATE_API_TOKEN   # Token from REST API Admin account
  validate_ssl: false

netbox:
  host: https://netbox.example.com
  token: YOUR_NETBOX_API_TOKEN
  validate_ssl: false
  site: MySite                      # Must match an existing site name in NetBox

options:
  permitted_subnets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
```

> The site must already exist in NetBox before running the script.

### Usage

```bash
# Always run a dry-run first — no changes written to NetBox
python3 fortigate_netbox_sync.py --config config.yaml --dry-run

# Live sync
python3 fortigate_netbox_sync.py --config config.yaml

# Verbose logging (useful for debugging)
python3 fortigate_netbox_sync.py --config config.yaml --debug
```

### Scheduling with cron

To run the sync automatically every hour, add the following line to your crontab (`crontab -e`):

```
0 * * * * /opt/fortigate-netbox-sync/.venv/bin/python /opt/fortigate-netbox-sync/fortigate_netbox_sync.py --config /opt/fortigate-netbox-sync/config.yaml >> /var/log/fortigate-netbox-sync.log 2>&1
```

> **Important:** always use the full path to the venv Python binary (`.venv/bin/python`), not `python3`. The cron environment does not activate the venv automatically.

Check your cron is registered:
```bash
crontab -l
```

Check the logs after the first scheduled run:
```bash
tail -50 /var/log/fortigate-netbox-sync.log
```

### Security

- Never commit `config.yaml` — it is excluded by `.gitignore`
- The FortiGate API account must be read-only
- Restrict trusted hosts to your NetBox server IP only

### License

MIT

---

## Français

Script Python pour synchroniser un FortiGate vers NetBox (DCIM + IPAM).

### Testé sur

| Appareil | FortiOS |
|---|---|
| FortiGate 100F | v7.4.12 |

### Ce qui est synchronisé

| Source (FortiGate) | Destination (NetBox) |
|---|---|
| Modèle + numéro de série | `dcim.devices` |
| Interfaces physiques | `dcim.interfaces` |
| Interfaces VLAN (nom + ID) | `dcim.interfaces` + `ipam.vlans` |
| IPs sur les interfaces | `ipam.ip_addresses` |
| Préfixes réseau | `ipam.prefixes` |

Tous les objets créés sont tagués `Source: fortigate-sync` + `netbox-synced` pour la traçabilité.
Le script est **idempotent** : relancer plusieurs fois ne crée pas de doublons — les objets existants sont mis à jour.

### Prérequis

- Python ≥ 3.10
- NetBox ≥ 4.0 (testé sur 4.6.x)
- Compte API REST en lecture seule sur le FortiGate

### Installation

```bash
git clone https://github.com/Grujowmi/fortigate-netbox-sync.git
cd fortigate-netbox-sync
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Compte API FortiGate

Créez un compte API REST en lecture seule sur votre FortiGate :

**System → Administrators → Create New → REST API Admin**
- Profile : `read-only`
- Trusted hosts : IP de votre serveur NetBox (ex : `172.17.1.207/32`)
- Cochez **"Don't filter VDOM traffic"** si vous avez des VDOMs

Copiez le token généré dans votre `config.yaml`.

### Configuration

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Renseignez vos valeurs :

```yaml
fortigate:
  host: 10.0.0.1                   # IP ou FQDN du FortiGate (nœud actif en HA)
  token: VOTRE_TOKEN_API_FORTIGATE
  validate_ssl: false

netbox:
  host: https://netbox.example.com
  token: VOTRE_TOKEN_API_NETBOX
  validate_ssl: false
  site: MonSite                     # Doit correspondre à un site existant dans NetBox

options:
  permitted_subnets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
```

> Le site doit exister dans NetBox avant de lancer le script.

### Utilisation

```bash
# Lancez toujours un dry-run d'abord — aucune écriture dans NetBox
python3 fortigate_netbox_sync.py --config config.yaml --dry-run

# Synchronisation réelle
python3 fortigate_netbox_sync.py --config config.yaml

# Logs verbeux (utile pour le debug)
python3 fortigate_netbox_sync.py --config config.yaml --debug
```

### Planification avec cron

Pour lancer la sync automatiquement toutes les heures, ajoutez la ligne suivante dans votre crontab (`crontab -e`) :

```
0 * * * * /opt/fortigate-netbox-sync/.venv/bin/python /opt/fortigate-netbox-sync/fortigate_netbox_sync.py --config /opt/fortigate-netbox-sync/config.yaml >> /var/log/fortigate-netbox-sync.log 2>&1
```

> **Important :** utilisez toujours le chemin absolu vers le Python du venv (`.venv/bin/python`), pas `python3`. L'environnement cron n'active pas le venv automatiquement.

Vérifiez que le cron est bien enregistré :
```bash
crontab -l
```

Consultez les logs après le premier run planifié :
```bash
tail -50 /var/log/fortigate-netbox-sync.log
```

### Sécurité

- Ne commitez **jamais** `config.yaml` — il est exclu par `.gitignore`
- Le compte API FortiGate doit être en lecture seule
- Restreignez les trusted hosts à l'IP de votre serveur NetBox uniquement

### Licence

MIT
