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
        // consistency: "strong" is critical — without it, rapid refreshes
        // can read a stale null and reset the counter, allowing extra attempts.
        const store = getStore({ name: "plays", consistency: "strong" });

        let used = 0;
        let storedMax = max;

        const raw = await store.get(id, { type: "text" });
        if (raw) {
            const record = JSON.parse(raw);
            used      = record.used;
            storedMax = record.max; // always trust the server's stored max, not the client
        }

        // Already used all attempts — block, don't increment
        if (used >= storedMax) {
            return Response.json({ used, blocked: true });
        }

        // Has attempts remaining — increment and allow
        const next = used + 1;
        await store.set(id, JSON.stringify({ used: next, max: storedMax }));
        return Response.json({ used: next, blocked: false });

    } catch (e) {
        console.error("Function error:", e);
        return new Response("Storage error", { status: 500 });
    }
};
