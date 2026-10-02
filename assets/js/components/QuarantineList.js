/**
 * Quarantine & recovery panel.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, LoadError, ConfirmDialog } from './ui.js';
import { useStore } from '../store.js';
import { useIsAdvancedView } from './ViewMode.js';
import { usePaged, ListSearch, matchesQuery } from './PaginatedList.js';

export function QuarantineList() {
	const store = useStore();
	const advanced = useIsAdvancedView();
	const [ items, setItems ] = useState( null );
	const [ loadErr, setLoadErr ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ query, setQuery ] = useState( '' );
	const [ confirm, setConfirm ] = useState( null ); // { title, message, consequence, confirmLabel, danger, key, run }

	// On failure `items` must stay null, not silently become [] — that would render as "Empty,
	// no files are quarantined" with no indication the request actually failed.
	const load = () => {
		setLoadErr( null );
		api.get( '/quarantine' ).then( ( d ) => setItems( d.items || [] ) ).catch( ( e ) => setLoadErr( e.message || 'Failed to load quarantined files.' ) );
	};
	useEffect( () => { load(); }, [] );

	const filtered = ( items || [] ).filter( ( q ) => matchesQuery( q, query, [ 'original_path', 'reason' ] ) );
	const { pageItems: pagedItems, pager } = usePaged( filtered, 25 );

	const act = async ( endpoint, body, msg, key ) => {
		setBusy( key );
		try {
			const res = await api.post( endpoint, body );
			store.toast( res.message || msg, res.ok === false ? 'error' : 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const runConfirm = async () => {
		if ( ! confirm ) return;
		await confirm.run();
		setConfirm( null );
	};

	const recoverCore = () => setConfirm( {
		key: 'recover',
		title: 'Recover core files?',
		message: 'This rewrites every WordPress core file to match the official WordPress.org release, replacing anything that was modified or tampered with.',
		consequence: 'Any deliberate customization made directly to core files (not a plugin or theme) will be lost. This does not touch your plugins, themes, or database.',
		confirmLabel: 'Recover Core Files',
		run: () => act( '/incident/recover-core', {}, 'Core recovery complete.', 'recover' ),
	} );

	const resetPerms = () => setConfirm( {
		key: 'perms',
		title: 'Reset file permissions?',
		message: 'Resets all files and folders across the WordPress install to WordPress’s recommended secure permissions.',
		consequence: advanced
			? 'Folders become 755, files become 644. If your host requires different permissions for something to work, this can temporarily break it.'
			: 'If your host requires different permissions for something to work, this can temporarily break it.',
		confirmLabel: 'Reset Permissions',
		run: () => act( '/incident/reset-permissions', {}, 'Permissions reset.', 'perms' ),
	} );

	const restoreItem = ( id ) => setConfirm( {
		key: 'r' + id,
		title: 'Restore this file?',
		message: 'Puts the file back at its original location, exactly as it was when it was quarantined.',
		consequence: 'Only do this if you’re sure it was a false positive — if it really was malicious, restoring it re-activates it.',
		confirmLabel: 'Restore File',
		run: () => act( '/quarantine/restore', { id }, 'Restored.', 'r' + id ),
	} );

	return h(
		Fragment,
		null,
		h( ConfirmDialog, {
			open: !! confirm,
			title: confirm ? confirm.title : '',
			message: confirm ? confirm.message : '',
			consequence: confirm ? confirm.consequence : '',
			confirmLabel: confirm ? confirm.confirmLabel : 'Confirm',
			busy: !! confirm && busy === confirm.key,
			danger: true,
			onCancel: () => setConfirm( null ),
			onConfirm: runConfirm,
		} ),
		h(
			Card,
			{ title: 'Recovery tools' },
			h( 'p', null, 'Repair tampered core files from WordPress.org, or normalize file permissions across the install.' ),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { variant: 'primary', disabled: !! busy, onClick: recoverCore }, busy === 'recover' ? 'Recovering…' : 'Recover core files' ),
				h( Button, { disabled: !! busy, onClick: resetPerms }, busy === 'perms' ? 'Resetting…' : 'Reset permissions' )
			)
		),

		h(
			Card,
			{
				title: 'Quarantined files',
				actions: h( Fragment, null,
					items && items.length > 0 && h( Button, { variant: 'danger', disabled: !! busy, onClick: clearAll }, busy === 'clear' ? 'Clearing…' : 'Delete all' ),
					' ',
					items ? h( Badge, { tone: items.length ? 'warning' : 'success' }, items.length ) : null
				),
			},
			! items ? ( loadErr ? h( LoadError, { message: loadErr, onRetry: load } ) : h( Spinner, null ) )
				: items.length === 0 ? h( EmptyState, { icon: '🧪', title: 'Empty', hint: 'No files are quarantined.' } )
				: h( Fragment, null,
						items.length > 5 && h( 'div', { className: 'ts-toolbar', style: { margin: '0 0 12px' } },
							h( ListSearch, { value: query, onChange: setQuery, placeholder: 'Search path or reason…' } )
						),
						filtered.length === 0
							? h( EmptyState, { icon: '🔍', title: 'No matching files', hint: 'Try a different search term.' } )
							: h( 'table', { className: 'ts-table' },
								h( 'thead', null, h( 'tr', null,
									h( 'th', null, 'Original path' ), h( 'th', null, 'Reason' ), h( 'th', null, 'Size' ), h( 'th', null, 'When' ), h( 'th', null, 'Actions' )
								) ),
								h( 'tbody', null, pagedItems.map( ( q ) =>
									h( 'tr', { key: q.id },
										h( 'td', { className: 'ts-uri', title: q.original_path }, q.original_path ),
										h( 'td', null, q.reason ),
										h( 'td', null, fmtSize( q.size ) ),
										h( 'td', null, q.created_at ),
										h( 'td', null,
											h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => restoreItem( q.id ) }, 'Restore' ),
											' ',
											h( Button, { variant: 'danger', disabled: !! busy, onClick: () => deleteItem( q.id ) }, 'Delete' )
										)
									)
								) )
							),
						pager
				  )
		)
	);

	function deleteItem( id ) {
		setConfirm( {
			key: 'd' + id,
			title: 'Delete this quarantined file?',
			message: 'Permanently deletes the file. It will not be restorable afterward.',
			confirmLabel: 'Delete File',
			run: () => act( '/quarantine/delete', { id }, 'Deleted.', 'd' + id ),
		} );
	}

	function clearAll() {
		setConfirm( {
			key: 'clear',
			title: 'Delete all quarantined files?',
			message: `Permanently deletes all ${ ( items || [] ).length } quarantined file(s). None will be restorable afterward.`,
			confirmLabel: 'Delete All',
			run: () => act( '/quarantine/clear', {}, 'All quarantined files deleted.', 'clear' ),
		} );
	}
}

function fmtSize( bytes ) {
	bytes = Number( bytes ) || 0;
	if ( bytes < 1024 ) return bytes + ' B';
	if ( bytes < 1048576 ) return ( bytes / 1024 ).toFixed( 1 ) + ' KB';
	return ( bytes / 1048576 ).toFixed( 1 ) + ' MB';
}
