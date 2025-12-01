const dotenv = require('dotenv');
dotenv.config();

const db = require('./db');
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;
const OAUTH_STATE_COOKIE = 'oauth_state';
const STATE_TTL_MS = 10 * 60 * 1000;

// Behind a reverse proxy (e.g., nginx/Cloudflare) we want the real client IP.
app.set('trust proxy', true);

const pendingStates = new Map();

const httpClient = axios.create({
  timeout: Number(process.env.HTTP_TIMEOUT_MS || 10000)
});

function cleanupStates() {
  const now = Date.now();
  for (const [state, meta] of pendingStates.entries()) {
    if (now - meta.createdAt > STATE_TTL_MS) {
      pendingStates.delete(state);
    }
  }
}

app.use(cookieParser());

app.get('/auth/twitch', (req, res) => {
  const scope = req.query.scope || "clips:edit";
  cleanupStates();

  const state = crypto.randomBytes(16).toString('hex');
  pendingStates.set(state, {
    createdAt: Date.now()
  });

  res.cookie(OAUTH_STATE_COOKIE, state, {
    httpOnly: true,
    secure: app.get('env') !== 'development',
    sameSite: 'lax',
    maxAge: STATE_TTL_MS
  });

  const params = new URLSearchParams({
    client_id: process.env.TWITCH_CLIENT_ID,
    redirect_uri: process.env.TWITCH_REDIRECT_URI,
    response_type: "code",
    scope,
    state
  }).toString();

  const twitchOAuthUrl = `https://id.twitch.tv/oauth2/authorize?${params}`;
  res.redirect(twitchOAuthUrl);
});

app.get('/auth/twitch/callback', async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;
    const stateCookie = req.cookies[OAUTH_STATE_COOKIE];

    if (!code) return res.status(400).send('No code provided');
    if (!state || !stateCookie || state !== stateCookie) {
        return res.status(400).send('Invalid OAuth state');
    }

    const storedState = pendingStates.get(state);
    if (!storedState || Date.now() - storedState.createdAt > STATE_TTL_MS) {
        pendingStates.delete(state);
        res.clearCookie(OAUTH_STATE_COOKIE);
        return res.status(400).send('OAuth state expired – bitte neu versuchen.');
    }

    pendingStates.delete(state);
    res.clearCookie(OAUTH_STATE_COOKIE);

    try {
        // Access Token holen
        const tokenRes = await httpClient.post('https://id.twitch.tv/oauth2/token', null, {
            params: {
                client_id: process.env.TWITCH_CLIENT_ID,
                client_secret: process.env.TWITCH_CLIENT_SECRET,
                code,
                grant_type: 'authorization_code',
                redirect_uri: process.env.TWITCH_REDIRECT_URI
            }
        });
        const { access_token, refresh_token } = tokenRes.data;

        // User-Info holen
        const userRes = await httpClient.get('https://api.twitch.tv/helix/users', {
            headers: {
                'Authorization': `Bearer ${access_token}`,
                'Client-Id': process.env.TWITCH_CLIENT_ID
            }
        });

        const user = userRes.data.data[0];

        // Token speichern!
        db.setToken(user.id, access_token, refresh_token, (err, api_token, meta = {}) => {
            if (err) {
                console.error('Token konnte nicht gespeichert werden:', err);
                return res.status(500).send('Token konnte nicht gespeichert werden.');
            }

            if (!api_token) {
                console.error('Callback erhielt keinen API-Token trotz erfolgreichem Speichern.', { userId: user.id });
                return res.status(500).send('Token konnte nicht ermittelt werden.');
            }

            const suffix = meta.isNew ? '' : '&existing=true';
            res.redirect(`/done?api_token=${api_token}${suffix}`);
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Fehler beim Twitch-Login');
    }
});

app.get('/done', (req, res) => {
    const api_token = req.query.api_token;
    const existing = req.query.existing === 'true';
    if (!api_token) return res.status(400).send("Fehler: Kein Token!");

    const headingText = existing
        ? 'Dein bisheriger API-Token bleibt gültig. Hier sind die Codes, falls du sie erneut brauchst.'
        : 'Hier sind die Codes für deinen Bot:';
    const reuseNote = existing
        ? 'Du kannst deinen bestehenden Command weiterverwenden. Falls du ihn neu anlegen möchtest, folge diesen Schritten:<br>'
        : '';

    const commands = {
        streamelements: `${'${'}customapi.https://clip.bytemike.de/twitch/clips/create/${api_token}?channel=${'${'}channel}}`,
        nightbot: `$(urlfetch https://clip.bytemike.de/twitch/clips/create/${api_token}?channel=$(channel))`,
        moobot: `https://clip.bytemike.de/twitch/clips/create/${api_token}?channel=$(channel)`,
        fossabot: `$(customapi https://clip.bytemike.de/twitch/clips/create/${api_token}?channel=$(channel))`,
        streamlabs: `$readapi(https://clip.bytemike.de/twitch/clips/create/${api_token}?channel=$mychannel)`
    };

    res.send(`
    <!DOCTYPE html>
    <html lang="de">
    <head>
    <meta charset="UTF-8">
    <title>Clip Command</title>
    <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #16171a; color: #fff; text-align: center; }
    h2 { margin-top: 2em; font-size: 2em; }
    .commands { margin: 2em auto; display: inline-block; text-align: left; }
    .cmd { background: #222; border-radius: 8px; padding: 1em; margin-bottom: 1.2em; box-shadow: 0 2px 8px #0006;}
    code { color: #b4c7fc; font-size: 1.05em; display: block; }
    button.copy-btn {
        background: #9147ff; color: #fff; border: none; border-radius: 6px; padding: 0.5em 1.2em;
        margin-top: 0.7em; font-size: 1em; cursor: pointer; transition: background 0.15s;
    }
    button.copy-btn:hover { background: #b27fff; }
    .success { color: #7fff7f; margin-top: 0.6em; }
    .explanation { color: #eee; font-size: 0.98em; margin-top: 1em; background: #18181b; padding: 0.7em 1em; border-radius: 6px;}
    </style>
    </head>
    <body>
    <h2>Fertig! ${headingText}</h2>
    <div class="commands">
    <div class="cmd">
    <b>StreamElements:</b><br>
    <code id="streamelements-cmd">${commands.streamelements}</code>
    <button class="copy-btn" onclick="copyCmd('streamelements-cmd', this)">Kopieren</button>
    <div class="explanation">
    <b>So verwendest du diesen Code:</b><br>
    ${reuseNote}Trage diesen Code als <b>Response</b> bei einem neuen Custom Command in <a href="https://streamelements.com/dashboard/bot/commands/custom" target="_blank" rel="noopener" style="color:#b4c7fc;">StreamElements</a> ein.<br>
    <a href="https://bytemike.de/wp-content/uploads/2025/05/streamelements.gif" target="_blank" style="color:#b4c7fc;">Hier findest du eine Schritt-für-Schritt Anleitung</a>
    </div>
    </div>
    <div class="cmd">
    <b>Nightbot:</b><br>
    <code id="nightbot-cmd">${commands.nightbot}</code>
    <button class="copy-btn" onclick="copyCmd('nightbot-cmd', this)">Kopieren</button>
    <div class="explanation">
    <b>So verwendest du diesen Code:</b><br>
    ${reuseNote}Füge den kopierten Code als <b>Message</b> für deinen neuen oder bestehenden Command auf <a href="https://nightbot.tv/commands/custom" target="_blank" rel="noopener" style="color:#b4c7fc;">nightbot.tv</a> ein.<br>
    <a href="https://bytemike.de/wp-content/uploads/2025/05/nightbot.gif" target="_blank" style="color:#b4c7fc;">Hier findest du eine Schritt-für-Schritt Anleitung</a>
    </div>
    </div>
    <div class="cmd">
    <b>Moobot:</b><br>
    <code id="moobot-cmd">${commands.moobot}</code>
    <button class="copy-btn" onclick="copyCmd('moobot-cmd', this)">Kopieren</button>
    <div class="explanation">
    <b>So verwendest du diesen Code:</b><br>
    ${reuseNote}Füge den kopierten Code als <b>Response</b> für deinen neuen oder bestehenden Command im <a href="https://moo.bot" target="_blank" rel="noopener" style="color:#b4c7fc;">moo.bot Dashboard</a> ein.<br>
    <a href="https://bytemike.de/wp-content/uploads/2025/05/moobot.gif" target="_blank" style="color:#b4c7fc;">Hier findest du eine Schritt-für-Schritt Anleitung</a>
    </div>
    </div>
    <div class="cmd">
    <b>Fossabot:</b><br>
    <code id="fossabot-cmd">${commands.fossabot}</code>
    <button class="copy-btn" onclick="copyCmd('fossabot-cmd', this)">Kopieren</button>
    <div class="explanation">
    <b>So verwendest du diesen Code:</b><br>
    ${reuseNote}Setze diesen Code als <b>Response</b> für einen neuen oder bestehenden Command in <a href="https://fossabot.com" target="_blank" rel="noopener" style="color:#b4c7fc;">Fossabot</a> ein.<br>
    <a href="https://bytemike.de/wp-content/uploads/2025/05/fossabot.gif" target="_blank" style="color:#b4c7fc;">Hier findest du eine Schritt-für-Schritt Anleitung</a>
    </div>
    </div>
    <div class="cmd">
    <b>Streamlabs Chatbot:</b><br>
    <code id="streamlabs-cmd">${commands.streamlabs}</code>
    <button class="copy-btn" onclick="copyCmd('streamlabs-cmd', this)">Kopieren</button>
    <div class="explanation">
    <b>So verwendest du diesen Code:</b><br>
    ${reuseNote}Füge den kopierten Code als <b>Response</b> für deinen neuen oder bestehenden Command im <a href="https://streamlabs.com/dashboard#/cloudbot/mod-tools" target="_blank" rel="noopener" style="color:#b4c7fc;">Streamlabs Dashboard</a> ein.
    </div>
    </div>
    </div>
    <a href="https://bytemike.de/" style="display:block;margin-top:30px;color:#b4c7fc;">Zurück zur Startseite</a><br><br>
    <script>
    function copyCmd(id, btn) {
        const code = document.getElementById(id).innerText;
        navigator.clipboard.writeText(code).then(function() {
            btn.innerText = 'Kopiert!';
            setTimeout(() => btn.innerText = 'Kopieren', 1200);
        });
    }
    </script>
    </body>
    </html>
    `);
});

function getClientIp(req) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp) return cfIp;

    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        const first = forwardedFor.split(',')[0].trim();
        if (first) return first;
    }

    return req.ip;
}

// z. B. max 1 Clip pro User alle 15 Sekunden
const clipsLimiter = rateLimit({
    windowMs: 15 * 1000,
    max: 1,
    keyGenerator: (req, res) => {
        return getClientIp(req);
    },
    handler: (req, res) => {
        console.warn('Rate Limit ausgelöst:', getClientIp(req));
        res.status(429).send('Bitte warte 15 Sekunden, bevor du den nächsten Clip erstellst.');
    }
});

// Limiter für alle Clips-Endpunkte aktivieren:
app.use('/twitch/clips', clipsLimiter);

// <--- HIER: clips.js einbinden!
const clipsRouter = require('./clips');
app.use('/twitch/clips', clipsRouter);

app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
