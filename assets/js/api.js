/**
 * Nonce-aware REST client for the Loyal Security API.
 *
 * Reads configuration injected by PHP (`window.TotalSecurityWP`) and attaches the
 * `X-WP-Nonce` header to every request so the WordPress REST cookie authentication
 * succeeds. All endpoints return the `{ success, data }` envelope; this unwraps `data`.
 */

const cfg = window.TotalSecurityWP || { root: '', nonce: '' };

async function request( path, { method = 'GET', body = null, params = null } = {} ) {
	let url = cfg.root.replace( /\/$/, '' ) + path;

	if ( params ) {
		// Callers commonly pass `value || undefined` for optional filters. URLSearchParams
		// stringifies `undefined`/`null` to the literal text "undefined"/"null" instead of
		// omitting the key, which servers then see as a real (non-empty) filter value —
		// so strip those out here rather than relying on every call site to do it.
		const cleaned = {};
		for ( const key in params ) {
			const value = params[ key ];
			if ( value !== undefined && value !== null ) cleaned[ key ] = value;
		}
		const qs = new URLSearchParams( cleaned ).toString();
		if ( qs ) url += ( url.includes( '?' ) ? '&' : '?' ) + qs;
	}

	const res = await fetch( url, {
		method,
		credentials: 'same-origin',
		headers: {
			'Content-Type': 'application/json',
			'X-WP-Nonce': cfg.nonce,
		},
		body: body ? JSON.stringify( body ) : null,
	} );

	// Read the raw body first so we can detect responses that are *almost* JSON but have
	// been corrupted by stray output (e.g. a compromised core/plugin file echoing a payload
	// before WordPress sends the REST JSON). Silently treating those as {} produces baffling
	// downstream errors (an undefined scan_id → HTTP 422), so we surface them explicitly.
	const raw = await res.text();
	let json = null;
	let parseFailed = false;
	try {
		json = raw ? JSON.parse( raw ) : {};
	} catch ( e ) {
		// Retry by trimming any garbage before the first JSON token — a classic injected
		// `echo` leaves valid JSON intact but prefixes it with noise.
		const start = raw.search( /[\[{]/ );
		if ( start > 0 ) {
			try {
				json = JSON.parse( raw.slice( start ) );
			} catch ( e2 ) {
				parseFailed = true;
			}
		} else {
			parseFailed = true;
		}
	}

	if ( parseFailed ) {
		const leak = raw.replace( /\s+/g, ' ' ).trim().slice( 0, 120 );
		const err = new Error(
			`The server returned a non-JSON response (HTTP ${ res.status }). This usually means injected or stray output is corrupting responses — check recently modified core/plugin files. Leading output: "${ leak }"`
		);
		err.status = res.status;
		err.code = 'totalsecwp_corrupt_response';
		err.raw = raw;
		throw err;
	}

	json = json || {};

	if ( ! res.ok ) {
		const message = json && json.message ? json.message : `Request failed (HTTP ${ res.status })`;
		const err = new Error( message );
		err.status = res.status;
		err.code = json && json.code ? json.code : 'http_error';
		// WP_Error's extra data (anything besides `status`) rides along in `json.data` — e.g.
		// AuthController's login-url failure attaches `nginx_snippet` here so a caller can show
		// the manual fallback even when the request itself failed, not just when it succeeded.
		err.data = json && json.data ? json.data : null;

		throw err;
	}

	// A 200 response that doesn't carry our { success, data } envelope but *did* contain a
	// leading-noise recovery means output was injected ahead of valid JSON — flag it.
	return json && Object.prototype.hasOwnProperty.call( json, 'data' ) ? json.data : json;
}

export const api = {
	get: ( path, params ) => request( path, { method: 'GET', params } ),
	post: ( path, body ) => request( path, { method: 'POST', body } ),
	put: ( path, body ) => request( path, { method: 'PUT', body } ),
	patch: ( path, body ) => request( path, { method: 'PATCH', body } ),
	del: ( path, body ) => request( path, { method: 'DELETE', body } ),
};

export const config = cfg;

/**
 * Save text returned by a REST endpoint as a file in the browser. Download endpoints return
 * JSON ({ filename, content, mime }) rather than streaming raw output; this turns that into a
 * normal file download via a temporary Blob URL.
 *
 * @param {string} filename Suggested file name.
 * @param {string} content  File contents.
 * @param {string} [mime]   MIME type.
 */
export function saveFile( filename, content, mime = 'application/octet-stream' ) {
	const blob = new Blob( [ content ], { type: mime } );
	const url  = URL.createObjectURL( blob );
	const a    = document.createElement( 'a' );
	a.href     = url;
	a.download = filename;
	document.body.appendChild( a );
	a.click();
	a.remove();
	setTimeout( () => URL.revokeObjectURL( url ), 0 );
}
