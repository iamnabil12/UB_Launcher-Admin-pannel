# UB Launcher Admin

Separate remote control panel for UB Launcher. It publishes:

- optional or mandatory update popups;
- latest and minimum launcher versions;
- update/download URL;
- optional What's New / release-notes URL;
- home banner, Discord banner, and UB logo;
- sidebar and social SVG icons.
- partner Minecraft servers shown inside the launcher;
- privacy-safe, opt-in user activity and launcher version monitoring.

The public launcher reads `https://launcher.unitedbangla.top/config.json`. The protected control panel is at `https://launcher.unitedbangla.top/admin`.

## Local development

Requires Node.js 20 or newer. No npm packages are required.

1. Copy `.env.example` to `.env` and set a unique password.
2. Run `npm start` (the start script loads `.env`).
3. Run `npm test` whenever you want to verify the API.
4. Open `http://127.0.0.1:8602/admin` and sign in with username `admin`.

Uploaded assets and the live configuration are stored under `data/`, which is excluded from Git.

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
IPv4: 62.72.57.85
Proxy: DNS only while issuing the certificate
```

After HTTPS works, Cloudflare proxy can be enabled and SSL/TLS mode should be `Full (strict)`.

## Update behavior

Set `currentVersion` to the release being replaced and `latestVersion` to the new release. Users see the update popup when `latestVersion` is newer than their installed launcher version. When `forceUpdate` is enabled, every installed version older than `latestVersion` must update and the Later button is hidden. A mandatory update is rejected unless a valid HTTPS update URL is also configured.
