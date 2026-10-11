/**
 * Lightweight global state via React context + useReducer.
 *
 * Holds cross-cutting UI state (toasts) so any component can raise notifications without
 * prop drilling. Module data is fetched locally per panel to keep the store small.
 */
import { h, createContext, useContext, useReducer, useCallback, useEffect } from './el.js';
import { api } from './api.js';

const StoreContext = createContext( null );

// Per-admin Basic/Advanced dashboard density — read synchronously from a data attribute the
// PHP side stamps on page load (see Assets.php) so the very first render already has the
// right value instead of flashing Advanced-then-Basic while the preference fetch is in flight.
function initialViewMode() {
	const root = document.getElementById( 'loyalsec-app' );
	return root && 'basic' === root.dataset.uiView ? 'basic' : 'advanced';
}

// Same data-attribute-seed trick as the view mode above, so an explicit dark/light choice is
// already applied to #loyalsec-app (see admin.css's [data-theme] rules) before React's first
// render — no flash of the ambient (OS/WP-core) theme first.
function initialTheme() {
	const root = document.getElementById( 'loyalsec-app' );
	const t = root && root.dataset.theme;
	return 'light' === t || 'dark' === t ? t : 'system';
}

// Applies (or clears) the data-theme attribute admin.css keys its explicit dark/light overrides
// off of (see [data-theme='dark']/[data-theme='light'] in admin.css). 'system' clears it so the
// ambient prefers-color-scheme / admin-color-midnight triggers decide, unchanged.
function applyThemeAttr( theme ) {
	const root = document.getElementById( 'loyalsec-app' );
	if ( ! root ) return;
	if ( 'light' === theme || 'dark' === theme ) {
		root.dataset.theme = theme;
	} else {
		delete root.dataset.theme;
	}
}

const initialState = {
	toasts: [],
	viewMode: initialViewMode(),
	theme: initialTheme(),
};

let toastSeq = 0;

function reducer( state, action ) {
	switch ( action.type ) {
		case 'TOAST_ADD':
			return { ...state, toasts: [ ...state.toasts, action.toast ] };
		case 'TOAST_REMOVE':
			return { ...state, toasts: state.toasts.filter( ( t ) => t.id !== action.id ) };
		case 'VIEW_MODE_SET':
			return { ...state, viewMode: action.view };
		case 'THEME_SET':
			return { ...state, theme: action.theme };
		default:
			return state;
	}
}

export function StoreProvider( { children } ) {
	const [ state, dispatch ] = useReducer( reducer, initialState );

	const toast = useCallback( ( message, kind = 'info', timeout = 4000 ) => {
		const id = ++toastSeq;
		dispatch( { type: 'TOAST_ADD', toast: { id, message, kind } } );
		if ( timeout ) {
			setTimeout( () => dispatch( { type: 'TOAST_REMOVE', id } ), timeout );
		}
		return id;
	}, [] );

	const dismissToast = useCallback( ( id ) => dispatch( { type: 'TOAST_REMOVE', id } ), [] );

	// Reconcile with the server once — the data-attribute seed above is last-known-good (can be
	// briefly stale after switching devices/browsers), the fetch is the source of truth.
	useEffect( () => {
		api.get( '/preferences/view' )
			.then( ( d ) => dispatch( { type: 'VIEW_MODE_SET', view: d.view === 'basic' ? 'basic' : 'advanced' } ) )
			.catch( () => {} );
	}, [] );

	useEffect( () => {
		api.get( '/preferences/theme' )
			.then( ( d ) => {
				const t = 'light' === d.theme || 'dark' === d.theme ? d.theme : 'system';
				dispatch( { type: 'THEME_SET', theme: t } );
				applyThemeAttr( t );
			} )
			.catch( () => {} );
	}, [] );

	const setViewMode = useCallback( ( view ) => {
		const next = 'basic' === view ? 'basic' : 'advanced';
		dispatch( { type: 'VIEW_MODE_SET', view: next } ); // optimistic — this is a low-stakes display preference
		api.post( '/preferences/view', { view: next } ).catch( () => {} );
	}, [] );

	const setTheme = useCallback( ( theme ) => {
		const next = 'light' === theme || 'dark' === theme ? theme : 'system';
		dispatch( { type: 'THEME_SET', theme: next } ); // optimistic — this is a low-stakes display preference
		applyThemeAttr( next );
		api.post( '/preferences/theme', { theme: next } ).catch( () => {} );
	}, [] );

	const value = { state, toast, dismissToast, setViewMode, setTheme };
	return h( StoreContext.Provider, { value }, children );
}

export function useStore() {
	return useContext( StoreContext );
}
