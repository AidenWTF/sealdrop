# SealDrop

A private file host for one person. You upload, you get a secret link, and only people
holding that link can see the file. Images and videos preview in the browser and embed in Discord.

## How only you can upload

- **There is no sign-up.** The only account is created by `npm run setup` on the server itself. No web route can create or change it.
- **Two factors.** Signing in needs your password and a code from your authenticator app. Each code works once.
- **Every upload is checked before a single byte is read.** It needs a live session, a matching origin and a CSRF token. Anything else gets refused, the connection is cut and the attempt is logged.
- **Storing a file needs a key only a signed-in session has.** The master key is unlocked by your password and kept only in memory, so without a login the server can't complete an upload at all.
- **Deny by default.** A route that isn't listed in `src/server.js` is a 404, and the server won't start if a route doesn't declare who may use it.
- **Brute force is capped.** 5 failures from one IP, or 20 in total, within 15 minutes blocks login attempts until the window passes.
- **Attackers can't lock you out of a browser you already use.** A browser that has signed in once is exempt from the 20-failure block, though it has its own limit of 5. This never replaces your password and code. A brand new browser can still be blocked during an attack, so sign in once on each device you rely on.

## How files stay private

- Each link holds a random 128-bit secret. It can't be guessed, and nothing on the server lists links publicly.
- Files, names, types and thumbnails are encrypted with AES-256-GCM using keys derived from that secret. Plaintext is never written to disk, including during upload and thumbnail creation.
- The server stores no usable copy of the link. The dashboard's copy is encrypted with your master key. Someone who steals the disk gets ciphertext, and can't read it without a link or your password.
- Tampered files are detected. A download is cut off instead of delivering altered data.
- Uploaded HTML, SVG and anything else outside a short list of media types always downloads and never runs on this site.

## What this does not protect against

Read these, because they are limits of the design:

- **Links are the access control.** Anyone you give a link to can view, download and forward it. Delete the file in the dashboard to revoke it.
- **Posting a link in Discord shares the file with Discord.** Everyone in the channel gets the link, and Discord's servers fetch and may keep a cached copy of the preview or file. Deleting it here can't remove Discord's copy. Don't post anything to Discord that Discord must not see.
- **The server can read files while serving them.** Discord can only build an embed if the server decrypts on request, so this isn't browser-only end-to-end encryption. Someone who takes over the running server could capture links or files as they pass through, or wait for you to sign in. Keep the server patched.
- **Your original file is served unchanged.** Photos can contain GPS location and other metadata. Remove it first if that matters.
- **A reverse proxy or CDN sees links.** Don't add access logs, and don't put this behind Cloudflare's proxy: it would see every link and decrypted file.
- **Someone with the disk can still see some facts.** File sizes, the number of files, upload times and whether a file has a thumbnail are visible. Contents, names and links aren't.
- **Your password protects the disk.** Your password alone unlocks both the master key and the authenticator secret in the vault, so a stolen backup can be attacked offline. Use the generated password, or a long random one. Changing your password later doesn't change the master key, so an old backup plus the old password still opens it.

## Deploying

You need a server with Docker and a domain pointing at it, with ports 80 and 443 open. Discord can only embed from a public HTTPS address.

```bash
cp .env.example .env
```

Set `DOMAIN` in `.env`. Ports are set there too: `HTTP_PORT` and `HTTPS_PORT` (default 80 and 443) are the ports on your server, and `APP_PORT` (default 18446) is the app's port inside Docker. Certificates are issued automatically only while 80 and 443 are reachable from the internet. Then create your account and start the site:

```bash
docker compose run --rm -it app node src/setup.js
```

```bash
docker compose up -d --build
```

Setup shows a QR code for your authenticator app. Leave the password blank to have a strong one generated, and keep it in a password manager.

## Running locally

Needs Node 22.9 or newer. ffmpeg is optional but needed for video thumbnails and embed sizes.

```bash
npm run setup
```

```bash
npm start
```

Then open http://127.0.0.1:8080. To use another port, set `PORT` and `PUBLIC_URL` in `.env` (for example `PORT=3000` and `PUBLIC_URL=http://127.0.0.1:3000`). Plain http is refused anywhere but localhost.

## Using it

- **Copy link** gives the page with preview and download button. Paste this into Discord.
- **Direct link** goes straight to the file. Paste it straight after `wget` and the file saves under its real name, even with spaces or brackets in the name.
- Download pages show each file's size, upload date in UTC and MD5. The MD5 lets someone check that a download isn't corrupted. It isn't proof against deliberate tampering, because MD5 collisions can be forged.
- Discord plays H.264 MP4 and WebM most reliably. It may show HEVC (H.265) videos without a player, and may not embed very large files. The link still works for downloading.

## Managing your account

Restart the server after any of these.

| Situation | What to do |
|---|---|
| Change password or authenticator | Run setup again. It asks for your current password. Signed-in browsers lose their lockout exemption until they next sign in. |
| Lost your authenticator | Run setup again with your password to enrol a new one. |
| Lost your password | Run setup with `--reset`. Existing links keep working, but those files disappear from your dashboard for good, so you can no longer delete them there. |

Back up the `data` directory to keep your files. Backups stay encrypted, and restoring one needs your password.

Security events (sign-ins, refused attempts, uploads, deletions) go to the server's output without any links or file names:

```bash
docker compose logs app
```

## Tests

```bash
npm test
```

Most tests are attacks: forged sessions, CSRF, replayed codes, path tricks, tampered ciphertext and a disk scan for leaked secrets. The real-media test is skipped unless ffmpeg is installed.
