/**
 * Entry module for the Loyal Security dashboard.
 *
 * Mounts the React app into the `#totalsecwp-app` node rendered by PHP. Uses the modern
 * `createRoot` API when available (WP 6.2+) and falls back to legacy `render`.
 */
import { h, render, createRoot } from './el.js';
import { App } from './components/App.js';

function mount() {
	const node = document.getElementById( 'totalsecwp-app' );
	if ( ! node ) return;

	// Clear the PHP-rendered boot placeholder.
	node.innerHTML = '';

	if ( createRoot ) {
		createRoot( node ).render( h( App, null ) );
	} else if ( render ) {
		render( h( App, null ), node );
	}
}

if ( document.readyState === 'loading' ) {
	document.addEventListener( 'DOMContentLoaded', mount );
} else {
	mount();
}
