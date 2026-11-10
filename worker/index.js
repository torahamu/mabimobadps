/**
 * Mobilay TW catalog mirror -- public, read-only GET proxy.
 * Japanese draft catalogs are hosted on GitHub Pages.
 * All unlisted catalogs are fetched directly from the original catalog API.
 * The packet_type_config_tw.enc snapshot is PINNED and FAILS CLOSED.
 *
 * Deploy this to your own Worker after reviewing distribution rights.
 */
const PAGES_API_BASE = 'https://torahamu.github.io/mabimoba/api/json/';
const ORIGINAL_API_BASE = 'https://api.mobilay.kr/api/json/';
const TRANSLATED = new Set([
  'dps_skill_names_tw.enc',
  'dps_buff_names_tw.enc',
  'barter_exchange_catalog_tw.enc',
  'item_lookup_catalog_tw.enc',
  'map_code_names_tw.enc',
  'job_code_names_tw.enc',
  'notice_monster_names_tw.enc',
]);
const PINNED_PACKET = 'packet_type_config_tw.enc';
const PINNED_SHA256 = '13F998F7BC75E36F4C0835F97C115398921830911BD9AE7AC54B3982C0EB4232';

function fail(status, msg, source = 'error') {
  return new Response(msg, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Mobilay-Mirror-Source': source,
    },
  });
}
function destination(base, file, sourceUrl) {
  const target = new URL(file, base);
  // Existing application uses ?t= to avoid cache, but no private query parameters.
  if (sourceUrl.searchParams.has('t')) target.searchParams.set('t', sourceUrl.searchParams.get('t'));
  return target;
}
async function upstreamGet(base, file, request, sourceUrl, isOfficial) {
  const headers = new Headers();
  // Never forward application keys to the public GitHub Pages origin.
  if (isOfficial) {
    for (const name of ['X-Lay-App', 'X-Lay-Key']) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
  }
  return fetch(destination(base, file, sourceUrl), {
    method: 'GET', headers, redirect: 'follow',
    cf: { cacheTtl: 0, cacheEverything: false },
    signal: AbortSignal.timeout(8000),
  });
}
function serve(upstream, source) {
  return new Response(upstream.body, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Mobilay-Mirror-Source': source,
    },
  });
}
async function digestHex(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
export default {
  async fetch(request) {
    const inputUrl = new URL(request.url);
    const match = /^\/api\/json\/([A-Za-z0-9_]+\.enc)$/.exec(inputUrl.pathname);
    if (request.method !== 'GET' || !match) return fail(404, 'Only GET /api/json/<catalog>.enc');
    const file = match[1];
    const pin = file === PINNED_PACKET;
    const localized = TRANSLATED.has(file);

    if (pin || localized) {
      try {
        const github = await upstreamGet(PAGES_API_BASE, file, request, inputUrl, false);
        if (github.ok) {
          if (pin) {
            // Encryption has a random nonce; this pins exact ciphertext bytes, not just JSON.
            const bytes = await github.arrayBuffer();
            if (await digestHex(bytes) !== PINNED_SHA256) {
              return fail(503, 'Pinned TW packet configuration SHA-256 mismatch', 'pinned-sha-mismatch');
            }
            return new Response(bytes, {
              status: 200,
              headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Cache-Control': 'no-store',
                'X-Mobilay-Mirror-Source': 'pinned-github-pages',
              },
            });
          }
          return serve(github, 'github-pages');
        }
        if (pin) return fail(503, `Pinned TW packet configuration missing (HTTP ${github.status})`, 'pinned-unavailable');
      } catch (err) {
        if (pin) return fail(503, 'Pinned TW packet configuration unavailable', 'pinned-unavailable');
      }
    }

    // Any non-listed catalog, and other names on GitHub errors, use live original.
    try {
      const official = await upstreamGet(ORIGINAL_API_BASE, file, request, inputUrl, true);
      if (!official.ok) return fail(502, `Original catalog returned HTTP ${official.status}`, 'original-error');
      return serve(official, localized ? 'official-fallback' : 'official');
    } catch (err) {
      return fail(502, 'Original catalog unavailable', 'original-error');
    }
  },
};
