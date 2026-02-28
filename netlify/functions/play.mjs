/**
 * Netlify Function v2: play.mjs
 * 
 * IMPORTANT: This file must be named play.mjs (not play.js)
 * The .mjs extension tells Netlify to use the v2 runtime which
 * automatically injects the Blobs context — fixing the MissingBlobsEnvironmentError.
 * 
 * DELETE the old play.js from netlify/functions/ and add this play.mjs instead.
 */

import { getStore } from "@netlify/blobs";

export default async (req) => {
    if (req.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
    }

    let id, max;
    try {
        const body = await req.json();
        id  = String(body.id  || "").trim();
        max = parseInt(body.max, 10);
    } catch (e) {
        return new Response("Bad Request", { status: 400 });
    }

    if (!id || id.length < 10 || isNaN(max) || max < 1 || max > 100) {
        return new Response("Bad Request", { status: 400 });
    }

    try {
        const store = getStore("plays");

        let record = null;
        try {
            const raw = await store.get(id, { type: "text" });
            if (raw) record = JSON.parse(raw);
        } catch (e) { /* key doesn't exist yet — first open */ }

        if (record) {
            const storedMax = record.max;
            const used = record.used;

            if (used >= storedMax) {
                return Response.json({ used, blocked: true });
            }

            const next = used + 1;
            await store.set(id, JSON.stringify({ used: next, max: storedMax }));
            return Response.json({ used: next, blocked: next >= storedMax });

        } else {
            await store.set(id, JSON.stringify({ used: 1, max }));
            return Response.json({ used: 1, blocked: 1 >= max });
        }

    } catch (e) {
        console.error("Function error:", e);
        return new Response("Storage error", { status: 500 });
    }
};
