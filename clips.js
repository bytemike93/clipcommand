const db = require('./db');
const express = require('express');
const axios = require('axios');

const router = express.Router();
const httpClient = axios.create({
  timeout: Number(process.env.HTTP_TIMEOUT_MS || 10000)
});

function classifyClipError(err) {
  const status = err?.response?.status;
  const msg = err?.response?.data?.message || err?.message || 'Unbekannter Fehler';
  const normalizedMsg = typeof msg === 'string' ? msg.toLowerCase() : '';

  if (!status) {
    if (err?.code === 'ECONNABORTED') {
      return {
        statusCode: 504,
        responseMessage: 'Twitch antwortet gerade nicht. Bitte versuche es gleich nochmal.',
        logLevel: 'warn',
        reason: 'twitch-timeout'
      };
    }
    return {
      statusCode: 503,
      responseMessage: 'Twitch konnte nicht erreicht werden. Bitte versuche es gleich nochmal.',
      logLevel: 'warn',
      reason: 'twitch-network-error'
    };
  }

  if (status === 404 && normalizedMsg.includes('offline')) {
    return {
      statusCode: 409,
      responseMessage: 'Clips können nur erstellt werden, wenn der Kanal live ist.',
      logLevel: 'info',
      reason: 'offline-channel'
    };
  }

  if (status === 429) {
    return {
      statusCode: 429,
      responseMessage: 'Twitch hat ein Clip-Limit erreicht. Bitte warte kurz und versuche es erneut.',
      logLevel: 'warn',
      reason: 'twitch-rate-limit'
    };
  }

  if (status === 403) {
    return {
      statusCode: 403,
      responseMessage: 'Twitch verweigert den Zugriff. Bitte autorisiere den Bot neu.',
      logLevel: 'warn',
      reason: 'twitch-forbidden'
    };
  }

  if (status === 404) {
    return {
      statusCode: 404,
      responseMessage: 'Twitch konnte den Kanal nicht finden. Bitte autorisiere den Bot neu.',
      logLevel: 'warn',
      reason: 'channel-not-found'
    };
  }

  if (status >= 500) {
    return {
      statusCode: 503,
      responseMessage: 'Twitch meldet einen internen Fehler. Bitte versuche es gleich nochmal.',
      logLevel: 'warn',
      reason: 'twitch-server-error'
    };
  }

  return {
    statusCode: 500,
    responseMessage: `Fehler beim Clip-Erstellen: ${msg}`,
    logLevel: 'error',
    reason: 'unexpected-error'
  };
}

function logClipError(prefix, err, classification) {
  const logMethod =
    classification.logLevel === 'info'
      ? console.info
      : classification.logLevel === 'warn'
      ? console.warn
      : console.error;

  logMethod(`${prefix}`, {
    reason: classification.reason,
    status: err?.response?.status,
    msg: err?.response?.data?.message,
    full: err?.response?.data,
    headers: err?.response?.headers,
    stack: err?.stack
  });
}

async function createClip(userId, accessToken) {
  const clipRes = await httpClient.post(
    `https://api.twitch.tv/helix/clips?broadcaster_id=${userId}`,
    {},
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Client-Id': process.env.TWITCH_CLIENT_ID
      }
    }
  );

  const clip = clipRes.data.data[0];
  if (!clip || !clip.id) {
    throw new Error('Twitch lieferte keine gültige Clip-ID zurück');
  }

  return `https://clips.twitch.tv/${clip.id}`;
}

async function invalidateToken(userId) {
  try {
    await db.deleteTokenByUserId(userId);
  } catch (err) {
    console.error('API-Token konnte nicht aus der Datenbank entfernt werden:', {
      userId,
      err
    });
  }
}

router.get('/create/:apiToken', async (req, res) => {
  const apiToken = req.params.apiToken;

  try {
    const [userId, accessToken, refreshToken] = await db.getTokenByApiTokenAsync(apiToken);

    if (!userId || !accessToken) {
      console.warn('Token oder User-ID fehlt:', { userId, apiTokenPresent: Boolean(apiToken) });
      return res.status(401).send('Kein gültiger API-Token.');
    }

    try {
      const clipUrl = await createClip(userId, accessToken);
      if (!clipUrl) return res.status(500).send('Clip konnte nicht erstellt werden.');
      return res.send(clipUrl);
    } catch (err) {
      const status = err?.response?.status;
      const msg = err?.response?.data?.message;

      if (status === 401) {
        if (refreshToken) {
          console.warn('Zugriffstoken ungültig, versuche Refresh...', { userId });
          try {
            const tokenRes = await httpClient.post('https://id.twitch.tv/oauth2/token', null, {
              params: {
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: process.env.TWITCH_CLIENT_ID,
                client_secret: process.env.TWITCH_CLIENT_SECRET
              }
            });

            const newAccessToken = tokenRes.data.access_token;
            const newRefreshToken = tokenRes.data.refresh_token || refreshToken;

            try {
              await db.setTokenAsync(userId, newAccessToken, newRefreshToken);
            } catch (persistErr) {
              console.error('Refresh-Token konnte nicht gespeichert werden:', persistErr);
              await invalidateToken(userId);
              return res.status(500).send('Fehler beim Speichern des Tokens.');
            }

            try {
              const clipUrl = await createClip(userId, newAccessToken);
              if (!clipUrl) return res.status(500).send('Clip konnte nach Refresh nicht erstellt werden.');
              return res.send(clipUrl);
            } catch (secondErr) {
              if (secondErr?.response?.status === 401) {
                await invalidateToken(userId);
                return res.status(401).send('Twitch-Token ungültig – bitte neu autorisieren.');
              }

              const classification = classifyClipError(secondErr);
              logClipError('Zweiter Versuch nach Token-Refresh fehlgeschlagen:', secondErr, classification);
              return res.status(classification.statusCode).send(
                classification.responseMessage || 'Fehler beim Clip-Erstellen nach Token-Refresh.'
              );
            }
          } catch (refreshErr) {
            console.error('Token-Refresh fehlgeschlagen:', refreshErr?.response?.data || refreshErr.message);
            await invalidateToken(userId);
            return res.status(401).send('Twitch-Token ungültig – bitte neu autorisieren.');
          }
        } else {
          await invalidateToken(userId);
          return res.status(401).send('Twitch-Token ungültig – bitte neu autorisieren.');
        }
      }

      const classification = classifyClipError(err);
      logClipError('Fehler beim Clip-Erstellen (erste Anfrage):', err, classification);
      return res.status(classification.statusCode).send(classification.responseMessage);
    }
  } catch (err) {
    console.error('Fehler beim Laden des Tokens:', err);
    return res.status(500).send('Fehler beim Abrufen des Tokens.');
  }
});

module.exports = router;
