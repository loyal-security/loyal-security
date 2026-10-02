/**
 * Thin re-export of WordPress core's bundled React (`wp.element`).
 *
 * Loading the dashboard as ES modules lets us `import` these helpers everywhere without a
 * build step. `h` is React.createElement; components are authored with nested `h()` calls,
 * which need no JSX compiler and therefore no Node toolchain.
 */
const wpEl = window.wp && window.wp.element ? window.wp.element : {};

export const h = wpEl.createElement;
export const Fragment = wpEl.Fragment;
export const render = wpEl.render;
export const createRoot = wpEl.createRoot || null;

export const useState = wpEl.useState;
export const useEffect = wpEl.useEffect;
export const useReducer = wpEl.useReducer;
export const useContext = wpEl.useContext;
export const createContext = wpEl.createContext;
export const useCallback = wpEl.useCallback;
export const useMemo = wpEl.useMemo;
export const useRef = wpEl.useRef;

/** Convenience: build a className from a map of { class: condition }. */
export function cx( ...parts ) {
	const out = [];
	for ( const p of parts ) {
		if ( ! p ) continue;
		if ( typeof p === 'string' ) {
			out.push( p );
		} else if ( typeof p === 'object' ) {
			for ( const key in p ) {
				if ( p[ key ] ) out.push( key );
			}
		}
	}
	return out.join( ' ' );
}
