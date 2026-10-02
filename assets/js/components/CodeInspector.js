/**
 * Code Inspector — a read-only, non-executing viewer for a flagged file.
 *
 * Fetches the file source plus a *dry-run* of the surgical fixer from
 * `GET /incident/inspect` (the server never writes and never executes the code; it only
 * reads bytes and pattern-matches). Lines the fixer would remove are highlighted in red so
 * the operator can see exactly what the malware is and what "Fix" would do before applying
 * it. Apply-fix / Delete / Quarantine can be triggered directly from the inspector.
 */
import { h, useState, useEffect } from '../el.js';
import { api } from '../api.js';
import { Button, Spinner } from './ui.js';
import { useStore } from '../store.js';

const OVERLAY = {
	position: 'fixed', inset: '0', background: 'rgba(0,0,0,0.55)', zIndex: '100000',
	display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px',
};
const PANEL = {
	background: '#fff', borderRadius: '8px', width: 'min(960px, 96vw)', maxHeight: '90vh',
	display: 'flex', flexDirection: 'column', boxShadow: '0 12px 48px rgba(0,0,0,0.35)', overflow: 'hidden',
};
const HEAD = {
	display: 'flex', alignItems: 'center', justifyContent: 'space-between',
	padding: '12px 16px', borderBottom: '1px solid #e2e4e7', gap: '12px',
};
const BODY = { overflow: 'auto', padding: '0', background: '#1e1e1e', flex: '1' };
const FOOT = { display: 'flex', gap: '8px', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid #e2e4e7', flexWrap: 'wrap' };

export function CodeInspector( { finding, onClose, onChanged } ) {
	const store = useStore();
	const [ data, setData ] = useState( null );
	const [ err, setErr ] = useState( '' );
	const [ busy, setBusy ] = useState( '' );
	const [ showClean, setShowClean ] = useState( false );

	useEffect( () => {
		let live = true;
		api.get( '/incident/inspect', { finding_id: finding.id, path: finding.path } )
			.then( ( d ) => { if ( live ) setData( d ); } )
			.catch( ( e ) => { if ( live ) setErr( e.message ); } );
		return () => { live = false; };
	}, [ finding.id ] );

	const run = async ( endpoint, key, confirmMsg ) => {
		if ( confirmMsg && ! window.confirm( confirmMsg ) ) return;
		setBusy( key );
		try {
			const res = await api.post( endpoint, { finding_id: finding.id, path: finding.path } );
			store.toast( ( res && res.message ) || 'Done.', res && res.reverted ? 'warning' : 'success' );
			onChanged && onChanged();
			onClose();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const fixable = data && data.fixable;

	return h( 'div', { style: OVERLAY, onClick: ( e ) => { if ( e.target === e.currentTarget ) onClose(); } },
		h( 'div', { style: PANEL },
			h( 'div', { style: HEAD },
				h( 'div', null,
					h( 'strong', null, '🔍 Code Inspector' ),
					h( 'div', { style: { fontSize: '12px', color: '#666', wordBreak: 'break-all' } }, finding.path )
				),
				h( Button, { variant: 'ghost', onClick: onClose }, '✕' )
			),
			h( 'div', { style: BODY },
				err
					? h( 'div', { style: { padding: '24px', color: '#f48771', fontFamily: 'monospace' } }, err )
					: ! data
						? h( 'div', { style: { padding: '24px' } }, h( Spinner, { label: 'Reading file (not executing)…' } ) )
						: renderCode( showClean ? splitClean( data ) : ( data.lines || [] ), showClean )
			),
			data && h( 'div', { style: FOOT },
				h( 'span', { style: { fontSize: '12px', color: fixable ? '#b32d2e' : '#666' } },
					fixable
						? `${ data.removed } line(s) would be removed by Fix`
						: 'No high-confidence injected snippet — this looks like a whole-file threat (delete/quarantine).'
				),
				data.truncated && h( 'span', { style: { fontSize: '12px', color: '#666' } }, '· truncated for display' ),
				h( 'span', { style: { flex: '1' } } ),
				fixable && h( Button, { variant: 'default', onClick: () => setShowClean( ! showClean ) }, showClean ? 'Show original' : 'Preview cleaned' ),
				fixable && h( Button, { variant: 'primary', disabled: !! busy, onClick: () => run( '/incident/fix-file', 'fix', 'Strip the highlighted injected line(s)? The original is backed up and auto-restored if the site breaks.' ) }, busy === 'fix' ? 'Fixing…' : 'Apply fix' ),
				h( Button, { variant: 'danger', disabled: !! busy, onClick: () => run( '/incident/remove-file', 'del', 'Delete this file? A backup is kept and the site is auto-restored if deletion breaks it.' ) }, busy === 'del' ? 'Deleting…' : 'Delete' ),
				h( Button, { variant: 'default', disabled: !! busy, onClick: () => run( '/quarantine/add', 'q' ) }, busy === 'q' ? 'Quarantining…' : 'Quarantine' )
			)
		)
	);
}

// Render numbered code lines; flag lines the fixer would drop.
function renderCode( lines, isClean ) {
	return h( 'pre', { style: { margin: '0', padding: '12px 0', fontFamily: 'Consolas, Menlo, monospace', fontSize: '12.5px', lineHeight: '1.5' } },
		lines.map( ( ln ) =>
			h( 'div', {
				key: ln.n,
				style: {
					display: 'flex',
					background: ln.removed ? 'rgba(190,45,46,0.28)' : 'transparent',
					borderLeft: ln.removed ? '3px solid #be2d2e' : '3px solid transparent',
				},
			},
				h( 'span', { style: { width: '44px', flex: '0 0 44px', textAlign: 'right', paddingRight: '12px', color: '#858585', userSelect: 'none' } }, String( ln.n ) ),
				h( 'span', { style: { color: ln.removed ? '#ffd7d7' : '#d4d4d4', whiteSpace: 'pre-wrap', wordBreak: 'break-all', paddingRight: '12px' } }, ln.text || ' ' )
			)
		)
	);
}

// The cleaned preview: show the post-fix source with no removal highlights.
function splitClean( data ) {
	return String( data.cleaned || '' ).split( /\r\n|\n|\r/ ).map( ( text, i ) => ( { n: i + 1, text, removed: false } ) );
}
