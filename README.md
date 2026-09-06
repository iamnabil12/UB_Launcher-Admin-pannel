# UB Launcher Admin

Separate remote control panel for UB Launcher. It publishes:

- optional or mandatory update popups;
- latest and minimum launcher versions;
- update/download URL;
- optional What's New / release-notes URL;
- home banner, Discord banner, and UB logo;
- sidebar and social SVG icons.
- partner Minecraft servers shown inside the launcher, with their favicon, MOTD, and version read automatically from the Minecraft server address;
- privacy-safe, opt-in user activity and launcher version monitoring.

The public launcher reads `https://launcher.unitedbangla.top/config.json`. The protected control panel is at `https://launcher.unitedbangla.top/admin`.

## Local development

Requires Node.js 20 or newer. No npm packages are required.

1. Copy `.env.example` to `.env` and set a unique administrator password containing at least 6 characters.
2. For local launcher testing, set `UB_PUBLIC_BASE_URL=http://127.0.0.1:8602` so uploaded assets and automatically fetched server favicons load from the local panel. Production deployments must use an HTTPS URL.
3. Run `npm start` (the start script loads `.env`).
4. Run `npm test` whenever you want to verify the API.
5. Open `http://127.0.0.1:8602/admin` and sign in with username `iamnabilgamer`.

Uploaded assets and the live configuration are stored under `data/`, which is excluded from Git.

## Administrator accounts

On the first start, `UB_ADMIN_PASSWORD` creates the main `iamnabilgamer` account. Override its username with `UB_PRIMARY_ADMIN_USERNAME` only when deploying a separate environment. The main account is protected by the server and cannot be removed from the panel or API. It and all later administrator passwords must contain at least 6 characters. After signing in, use the **Administrators** page to add more trusted people with their own username and password. Passwords are saved as one-way hashes in `data/administrators.json`; they cannot be viewed or recovered from the panel.

The web panel signs in through an `HttpOnly`, `SameSite=Strict` session cookie (also `Secure` in production HTTPS). Sessions expire after 12 hours, live only in server memory, and are revoked on logout or when the administrator is removed. Restarting the Node service therefore signs everyone out. Failed logins are limited per client address. Explicit HTTP Basic credentials remain accepted by protected API endpoints for compatibility, but the server never sends a browser Basic Auth challenge.

## User monitoring and privacy

The launcher sends analytics only when the user enables **Anonymous usage analytics** in Privacy settings. The dashboard can show anonymous install ID, launcher version, OS, architecture, locale, sessions, game launches, first/last seen, and online status based on recent heartbeats.

The current launcher does not have real Microsoft OAuth account data, so it does not collect usernames or email addresses. Those columns remain anonymous/`Not available`. Do not claim otherwise to users.

## VPS deployment

Clone this repository as `~/ub-launcher-admin`, create its `.env`, then install the included user service:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/ub-launcher-admin.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ub-launcher-admin
```

The VPS owner must install `deploy/nginx-launcher.conf` in Nginx and issue an HTTPS certificate for `launcher.unitedbangla.top`. Keep the Node service bound to `127.0.0.1`; only Nginx should be public.

For Cloudflare, create this DNS record first:

```text
Type: A
Name: launcher
IPv4: 213.35.106.78
Proxy: DNS only while issuing the certificate
```

After HTTPS works, Cloudflare proxy can be enabled and SSL/TLS mode should be `Full (strict)`.

## Update behavior

Set `currentVersion` to the release being replaced and `latestVersion` to the new release. Users see the update popup when `latestVersion` is newer than their installed launcher version. When `forceUpdate` is enabled, every installed version older than `latestVersion` must update and the Later button is hidden. A mandatory update is rejected unless a valid HTTPS update URL is also configured.
