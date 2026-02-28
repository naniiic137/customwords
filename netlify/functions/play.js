/**
 * Netlify Function: play.js
 *
 * Tracks how many times a puzzle link has been opened server-side.
 * This makes the attempt limit work across private tabs, different
 * browsers, and different devices — not just on one device via localStorage.
 *
 * Storage: Netlify Blobs (free, built-in, no external DB needed)
 *
 * POST /.netlify/functions/play
 * Body: { id: "<sha256 of url fragment>", max: 3 }
 * Returns: { used: 2, blocked: false }
 */

const { getStore } = require('@netlify/blobs');

exports.handler = async (event) => {
    /* Only allow POST */
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    let id, max;
    try {
        const body = JSON.parse(event.body || '{}');
        id  = String(body.id  || '').trim();
        max = parseInt(body.max, 10);
    } catch (e) {
        return { statusCode: 400, body: 'Bad Request' };
    }

    /* Validate inputs */
    if (!id || id.length < 10 || isNaN(max) || max < 1 || max > 100) {
        return { statusCode: 400, body: 'Bad Request' };
    }

    try {
        const store = getStore('plays');

        /* Load existing record for this link (if any) */
        let record = null;
        try {
            const raw = await store.get(id, { type: 'text' });
            if (raw) record = JSON.parse(raw);
        } catch (e) { /* key doesn't exist yet — first open */ }

        if (record) {
            /* Use the MAX that was stored on first open — ignore what the client sends now.
               This prevents someone from calling the function directly with a fake high max. */
            const storedMax = record.max;
            const used      = record.used;

            if (used >= storedMax) {
                /* Already exhausted */
                return respond(used, true);
            }

            /* Increment */
            const next = used + 1;
            await store.set(id, JSON.stringify({ used: next, max: storedMax }));
            return respond(next, next >= storedMax);

        } else {
            /* First time this link is opened — register it with the max from the encrypted payload.
               The client can't forge a higher max because max comes from the AES-GCM decrypted data. */
            await store.set(id, JSON.stringify({ used: 1, max: max }));
            return respond(1, 1 >= max);
        }

    } catch (e) {
        console.error('Blob store error:', e);
        return { statusCode: 500, body: 'Storage error' };
    }
};

function respond(used, blocked) {
    return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ used, blocked }),
    };
}
