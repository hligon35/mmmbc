# Deployment

This project is a static website + a Node/Express admin server (in this `admin/` folder) that also serves the public site from the repo root.

## Option A: Host on Render (recommended “for now”)

### 1) Create a Web Service

- **Repo**: connect your GitHub repo
- **Branch**: `admin`
- **Root Directory**: `admin`
- **Runtime**: Node

### 2) Build + start commands

- **Build Command**: `npm install`
- **Start Command**: `npm start`

### 3) Required environment variables

Set these in Render “Environment”:

- `ADMIN_EMAIL` = your master admin email
- `ADMIN_PASSWORD` = a strong password
- `SESSION_SECRET` = long random string

Recommended:

- `PUBLIC_BASE_URL` = `https://<your-service>.onrender.com`
- `TRUST_PROXY` = `true`
- `ENFORCE_HTTPS` = `true` (or omit; production default enforces HTTPS)
- `ENABLE_EXPORTS` = `true` (default) or `false` if you want to prevent exporting into repo-root files

Optional (gallery “CDN” mode):

- `GALLERY_URL_PREFIX` = empty (default) keeps URLs like `/ConImg/gallery/...`
- `GALLERY_URL_PREFIX` = `/cdn` makes new uploads/exported `gallery.json` point at `/cdn/ConImg/gallery/...`
- `GALLERY_URL_PREFIX` = `https://cdn.yourdomain.com` makes gallery.json use that CDN domain

Notes:

- The admin server now exposes a cache-friendly path: `/cdn/ConImg/gallery/...` with `Cache-Control: public, max-age=31536000, immutable`.
- Cloudflare is optional: you can put Cloudflare in front later and set `GALLERY_URL_PREFIX` to your CDN hostname.

### 4) Persist data + uploads (important)

Render’s filesystem is ephemeral unless you add a **Disk**. If you don’t add one, you’ll lose:
- logins/users
- uploaded docs/bulletins
- gallery uploads
- finance entries

Do this:

- Add a **Disk** and mount it at: `/var/data`
- Set:
  - `ADMIN_DATA_DIR=/var/data/data`
  - `ADMIN_UPLOADS_DIR=/var/data/uploads`
  - `SESSIONS_DIR=/var/data/sessions`

### 5) Health/log endpoints

When logged into the admin UI, you can call:
- `GET /api/admin/health`
- `GET /api/admin/logs?type=app&lines=300`
- `GET /api/admin/logs?type=audit&lines=300`

## Option B: Raspberry Pi local server (end game)

This is the “secure local server” approach: run Node on the Pi, store data on the SD/SSD, and optionally put nginx in front.

### 1) Recommended architecture

- Node app binds to `127.0.0.1:8787` (not directly exposed)
- nginx reverse-proxies to Node
- firewall allows only LAN access (or only specific IPs)

### 2) Install Node and app deps

On the Pi:

- Install Node 20 LTS
- Clone/pull the repo
- `cd admin && npm ci`

### 3) Create an env file

Create something like `/etc/mmmbc-admin.env`:

- `ADMIN_EMAIL=...`
- `ADMIN_PASSWORD=...`
- `SESSION_SECRET=...`
- `HOST=127.0.0.1`
- `PORT=8787`
- `TRUST_PROXY=true` (only if using nginx)
- `ENFORCE_HTTPS=false` (LAN-only HTTP; if you enable TLS at nginx, set `true`)
- `PUBLIC_BASE_URL=http://<pi-hostname>:8787` (or `https://...` if you terminate TLS)
- `ADMIN_DATA_DIR=/var/lib/mmmbc-admin/data`
- `ADMIN_UPLOADS_DIR=/var/lib/mmmbc-admin/uploads`
- `SESSIONS_DIR=/var/lib/mmmbc-admin/sessions`

### 4) systemd service

A ready-to-copy unit file is included at `admin/systemd/mmmbc-admin.service`.

Typical setup:

- `sudo mkdir -p /var/lib/mmmbc-admin/{data,uploads,sessions}`
- `sudo cp admin/systemd/mmmbc-admin.service /etc/systemd/system/mmmbc-admin.service`
- `sudo systemctl daemon-reload`
- `sudo systemctl enable --now mmmbc-admin`

### 5) nginx (optional but recommended)

- Reverse proxy `http://127.0.0.1:8787`
- Add TLS if you want HTTPS on LAN
- Add IP allowlisting (church office PCs only) if desired

### 6) Security checklist for LAN deployment

- Keep the admin UI LAN-only (no port forwarding)
- Use strong `ADMIN_PASSWORD` + enable MFA
- Back up `/var/lib/mmmbc-admin` regularly
- Keep Pi OS + Node updated
- Consider IP allowlist + fail2ban if exposed beyond LAN
