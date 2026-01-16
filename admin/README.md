# MMMBC Admin Dashboard

This folder adds a small local admin server (Node/Express) + an admin dashboard UI for managing:
- Photo gallery uploads + albums/tags
- Announcements
- Events calendar (exports to the existing `schedule.json` format)
- Document uploads (PDF bulletins/newsletters)
- Livestream embed settings + recurring schedule
- Settings (social links + basic theme colors/logo export)

## Setup

1. Install dependencies:

```bash
cd admin
npm install
```

2. Create `.env` from `.env.example` and set:

- `ADMIN_EMAIL` (master admin email)
- `ADMIN_PASSWORD` (master admin password)
- `SESSION_SECRET` (random long string)

3. Run:

```bash
npm start
```

Open:
- Admin Dashboard: `http://localhost:8787/admin/`
- Website (served by same server): `http://localhost:8787/`

## Notes on security

- The master password is **not** hardcoded. On startup, the server creates/updates the master admin account using env vars and stores only a **bcrypt hash** in `admin/data/users.json`.
- This is designed for a church office computer or a trusted server. If you deploy publicly, add HTTPS + backups and consider stronger auth.
