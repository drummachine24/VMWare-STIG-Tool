# VMware STIG Scan Tool

Linux Docker-based STIG compliance scanner for **VMware VCF / vSphere 9.x** with a web UI, selectable scan targets (PowerCLI + optional VCSA SSH), CKL output, and scheduled scans.

## Architecture

| Service    | Purpose                                      |
|-----------|-----------------------------------------------|
| `web`     | FastAPI + web UI on port **8080**             |
| `worker`  | CINC Auditor, PowerCLI, SAF CLI scan executor |
| `scheduler` | Celery Beat — checks schedules every minute |
| `postgres`| Scan history, vCenter configs, schedules      |
| `redis`   | Job queue                                   |

## Scan targets (selectable per job)

| Target              | Transport | Profile |
|---------------------|-----------|---------|
| ESXi hosts          | PowerCLI → vCenter | `.../esx/` |
| Virtual machines    | PowerCLI → vCenter | `.../vm/` |
| vCenter product     | PowerCLI → vCenter | `.../vcenter/` |
| vCenter appliance   | SSH → VCSA         | `vmware-cloud-foundation-vcsa-stig-baseline` |

## Quick start (Linux Docker host)

This project is designed to run on a **Linux machine with Docker**. Copy the project directory to your host, then follow these steps.

### What to copy

Copy the whole project folder **except** you do not need to copy a `.env` file — it will be created on the Linux host with fresh secrets.

```bash
# Example: from your workstation, copy to the Linux Docker host
scp -r "VMWare STIG Tool" user@your-linux-host:~/vmware-stig-tool
ssh user@your-linux-host
cd ~/vmware-stig-tool
```

### Automated first-time setup

```bash
bash scripts/first-time-setup.sh
```

This script will:
1. Check for Docker and Git
2. Create `.env` with a generated **Fernet key** (for encrypting vCenter passwords)
3. Download VMware STIG profiles into `stig-profiles/`
4. Auto-detect your VCF 9.x profile revision folder

### Manual setup (if you prefer step-by-step)

See [First-time setup walkthrough](#first-time-setup-walkthrough) below.

### Start the stack

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f web   # Ctrl+C to stop following logs
```

Open **http://your-linux-host-ip:8080**

### Install train-vmware plugin (required for real scans)

```bash
bash scripts/install-train-vmware.sh
```

---

## First-time setup walkthrough

### Step 1 — Prerequisites on the Linux host

- Docker Engine 24+ with Compose plugin (`docker compose version`)
- Git
- Outbound internet (to build images and clone STIG profiles)
- Network access from the worker container to vCenter on **443** (and **22** if using appliance SSH scans)

### Step 2 — Copy the project

Copy the directory to your Linux Docker host. Do **not** commit or share `.env` — create it on the server.

### Step 3 — Generate the Fernet key and create `.env`

The Fernet key encrypts vCenter passwords stored in the database.

**Option A — use the setup script (easiest):**

```bash
bash scripts/first-time-setup.sh
```

**Option B — generate manually:**

```bash
cp .env.example .env

# Generate Fernet key (pick ONE method that works on your host)

# Method 1: Python 3 with cryptography
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Method 2: One-off Docker container (no Python install needed)
docker run --rm python:3.12-slim sh -c \
  "pip install -q cryptography && python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""

# Method 3: OpenSSL-derived key (works without Python; our app accepts this format)
python3 -c "import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.urandom(32)).digest()).decode())"
```

Edit `.env` and paste the key:

```bash
nano .env
# Set:
#   CREDENTIAL_ENCRYPTION_KEY=<paste-fernet-key-here>
#   APP_SECRET_KEY=<any-long-random-string>
```

Also generate a random app secret:

```bash
openssl rand -base64 32
```

### Step 4 — Download STIG profiles

```bash
bash scripts/setup-stig-profiles.sh ./stig-profiles
```

Check which revision folder was downloaded:

```bash
ls stig-profiles/vcf/9.x/
# Example output: Y25M06-srg
```

Update `.env` if the folder name differs from the default:

```env
VCF_PROFILE_BASE=vcf/9.x/Y25M06-srg
```

### Step 5 — Build and start containers

```bash
docker compose up --build -d
```

First build takes **10–20 minutes** (worker installs PowerShell, CINC Auditor, PowerCLI, SAF CLI).

Check status:

```bash
docker compose ps
curl -s http://localhost:8080/health
```

### Step 6 — Install train-vmware plugin

```bash
bash scripts/install-train-vmware.sh
```

You should see `train-vmware` in the plugin list.

### Step 7 — First login to the web UI

1. Open `http://<linux-host-ip>:8080`
2. Go to **vCenters** → add your vCenter FQDN and API credentials
3. Click **Pre-flight** to verify connectivity
4. Go to **New Scan** → select targets → run

### Step 8 (optional) — Test UI without vCenter

Before connecting to production vCenter, you can verify the stack works:

```bash
# In .env set:
#   DRY_RUN=true

docker compose up -d --force-recreate web worker
```

Run a scan from the UI — it will produce placeholder JSON/CKL files without calling vCenter.

Set `DRY_RUN=false` when ready for real scans.

---

## Deploying updates on the RHEL Docker host

Docker runs on the **Linux server**, not on the Windows dev workstation. After pushing code changes to Git:

```bash
cd ~/vmware-stig-tool   # or your clone path on RHEL
bash scripts/rebuild-on-server.sh --prod
```

If you see `set: pipefail: invalid option name`, the script has Windows CRLF line endings. Fix on the server:

```bash
sed -i 's/\r$//' scripts/rebuild-on-server.sh scripts/*.sh worker/install-scan-tools.sh
```

This will:
1. `git pull` the latest code
2. Rebuild `web`, `worker`, and `scheduler` images (app code baked in via `COPY backend/app`)
3. Recreate containers using `docker-compose.prod.yml` (no `./backend/app` bind mount, no uvicorn `--reload`)

**What is baked into images (safe):** Python app, templates, static files, `requirements.txt`, worker scan tools installer.

**What stays mounted at runtime (not baked):** `data/reports`, `data/ckl-exports`, `data/secrets`, `stig-profiles`, certs, Postgres/Redis data.

For a quick dev-style deploy (bind mount still overrides app code from the host checkout):

```bash
bash scripts/rebuild-on-server.sh
```

Optional: tag a release before building:

```bash
export IMAGE_TAG=2026-07-02
bash scripts/rebuild-on-server.sh --prod
```

---

## Quick start (legacy summary)

## Usage workflow

1. **vCenters** — Add vCenter connection (API creds + optional SSH creds for appliance scans)
2. **Pre-flight** — Verify API, SSH, profiles, CINC Auditor, SAF CLI
3. **New Scan** — Select targets (ESXi / VM / vCenter Product / VCSA Appliance)
4. **Results** — Download JSON and CKL per target
5. **Schedules** — Cron-based recurring scans (default: `0 2 * * 0` = Sundays 02:00 UTC)

## Development / dry-run mode

Set in `.env`:

```
DRY_RUN=true
```

Scans produce placeholder JSON/CKL without calling CINC Auditor or vCenter — useful for UI testing without profiles or vCenter connectivity.

## API

- Swagger UI: http://localhost:8080/docs
- `GET /health`
- `POST /api/vcenters`
- `POST /api/vcenters/{id}/preflight?check_ssh=true`
- `POST /api/scans`
- `GET /api/scans/{id}/results`
- `POST /api/schedules`

## VCF 9.x toolchain (worker image)

- PowerShell 7.4+
- VCF PowerCLI 9.x modules (VMware.VimAutomation.*, VMware.Vsphere.SsoAdmin)
- CINC Auditor 7.x
- MITRE SAF CLI
- train-vmware 1.0.0 (installed from STIG profile bundle)

## VCSA appliance scan notes

- Enable SSH on vCenter temporarily
- Set root shell: `chsh -s /bin/bash root`
- Run appliance scan
- Optionally disable SSH afterward (may affect a vCenter *product* control that requires SSH disabled)

## Project layout

```
├── docker-compose.yml
├── backend/           # FastAPI app, UI templates, Celery tasks
├── worker/            # Scan worker Dockerfile + tool installer
├── scripts/           # STIG profile setup
├── stig-profiles/     # Mount point for dod-compliance-and-automation
└── data/reports/      # Scan JSON + CKL output
```

## Troubleshooting

| Issue | Check |
|-------|-------|
| `set: pipefail: invalid option name` | Windows CRLF line endings — run `sed -i 's/\r$//' scripts/*.sh worker/install-scan-tools.sh` on Linux |
| Profiles not found | Run `setup-stig-profiles.sh`, verify `VCF_PROFILE_BASE` |
| PowerCLI connection fails | Pre-flight page, credentials, DNS from container |
| No CKL files | SAF CLI in worker: `docker compose exec worker saf --version` |
| train-vmware errors | Plugin installed in worker as the celery user |
| Long scans timeout | Increase `SCAN_TIMEOUT_SECONDS` in `.env` |

## References

- [vmware/dod-compliance-and-automation](https://github.com/vmware/dod-compliance-and-automation)
- [Audit ESX 9.X (Broadcom STIG docs)](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/stig/9-1/vcf-stig-documentation/docs-tutorials-cloud-foundation-9x-product-esx-audit9-esx-audit9-esx.html)
- [Audit VCF vCenter Server 9.X (appliance SSH)](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/stig/9-1/vcf-stig-documentation/docs-tutorials-cloud-foundation-9x-appliances-vcenter-server-audit9-vcsa.html)
- [MITRE SAF CLI](https://saf-cli.mitre.org/)
