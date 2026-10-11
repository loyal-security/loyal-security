/**
 * Repair Center — clean reinstall of core & WordPress.org plugins, best-effort per-file
 * fixes for premium/custom code, and rollback of the backups those operations create.
 *
 * Unlike Quarantine (which isolates a file and can break the site), repair restores a working,
 * clean copy: core is re-fetched for the running version, wp.org plugins are reinstalled, and
 * code that can't be re-fetched is cleaned in place with an automatic backup + health check.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, LoadError } from './ui.js';
import { useStore } from '../store.js';
import { useJobPoller, JobProgress } from './JobProgress.js';
import { ProGate } from './ProGate.js';
import { usePaged, ListSearch, matchesQuery } from './PaginatedList.js';

function fmtBytes( n ) {
	n = Number( n ) || 0;
	if ( n < 1024 ) return n + ' B';
	if ( n < 1048576 ) return ( n / 1024 ).toFixed( 1 ) + ' KB';
	if ( n < 1073741824 ) return ( n / 1048576 ).toFixed( 1 ) + ' MB';
	return ( n / 1073741824 ).toFixed( 2 ) + ' GB';
}

export function RepairCenter() {
	const store = useStore();
	const [ inv, setInv ] = useState( null );
	const [ invError, setInvError ] = useState( null );
	const [ backups, setBackups ] = useState( null );
	const [ backupsError, setBackupsError ] = useState( null );
	const [ summary, setSummary ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ coreResult, setCoreResult ] = useState( null );

	// One background job at a time (plugin reinstall / clear backups). The
	// dashboard polls /jobs/{id}; if cron never starts it, the user can retry inline (sync).
	const [ job, setJob ] = useState( null ); // { id, title, retry: {endpoint, body} }
	// Slug of the plugin whose single-plugin reinstall is in flight, so its row (and only its
	// row) shows "Working…" — the previous per-row check keyed off a busy value this flow never
	// set, so the label never appeared.
	const [ repairingSlug, setRepairingSlug ] = useState( '' );
	const [ pluginQuery, setPluginQuery ] = useState( '' );
	const [ backupQuery, setBackupQuery ] = useState( '' );
	const jobSnap = useJobPoller( job && job.id, {
		onDone: ( j ) => {
			store.toast( ( j.result && j.result.message ) || j.step || 'Done.', 'success' );
			setJob( null );
			setRepairingSlug( '' );
			loadInv();
			loadBackups();
		},
		onError: ( j ) => {
			store.toast( j.error || 'Operation failed.', 'error' );
			setJob( null );
			setRepairingSlug( '' );
			loadInv();
			loadBackups();
		},
	} );

	// On failure `inv`/`backups` MUST stay null, not silently become an empty inventory — this
	// panel exists to fix malware-affected files, so an API failure rendering as "None, every
	// installed plugin is fine" would be a false all-clear with no error shown to the user at all.
	const loadInv = () =>
		api.get( '/incident/repairs' ).then( ( d ) => { setInv( d ); setInvError( null ); } )
			.catch( ( e ) => {
				store.toast( e.message, 'error' );
				setInvError( e.message || 'Failed to load the repair inventory.' );
			} );
	const loadBackups = () =>
		api.get( '/incident/backups' )
			.then( ( d ) => { setBackups( d.items || [] ); setSummary( d.summary || null ); setBackupsError( null ); } )
			.catch( ( e ) => {
				store.toast( e.message, 'error' );
				setBackupsError( e.message || 'Failed to load repair backups.' );
			} );

	useEffect( () => {
		loadInv();
		loadBackups();
	}, [] );

	// Start an async job; remember how to re-run it synchronously if the queue stalls.
	const startJob = async ( endpoint, body, title ) => {
		if ( job ) return;
		// Show the job card (and its "Starting…" JobProgress state, which it already renders
		// for a null snapshot) immediately, rather than leaving the trigger button looking
		// inert while the server builds the job.
		setJob( { id: null, title, retry: { endpoint, body } } );
		try {
			const res = await api.post( endpoint, body );
			if ( res && res.job_id ) {
				setJob( { id: res.job_id, title, retry: { endpoint, body } } );
			} else {
				// Server ran it inline (sync) — refresh.
				store.toast( ( res && res.message ) || 'Done.', 'success' );
				setJob( null );
				loadInv();
				loadBackups();
			}
		} catch ( e ) {
			setJob( null );
			store.toast( e.message, 'error' );
		}
	};

	// Fallback when the background job won't start (host has no working loopback cron): re-run
	// the same operation synchronously. Warns it may take longer / risk a gateway timeout.
	const runSyncFallback = async () => {
		if ( ! job || ! job.retry ) return;
		const { endpoint, body } = job.retry;
		const title = job.title;
		setJob( null );
		setBusy( 'sync' );
		store.toast( title + ' — running now. Large plugins may take 1–2 minutes; please wait.', 'info' );
		try {
			const res = await api.post( endpoint, { ...body, sync: true } );
			store.toast( ( res && res.message ) || 'Done.', 'success' );
		} catch ( e ) {
			if ( e.status === 504 || e.code === 'loyalsec_corrupt_response' || /timeout|aborted/i.test( e.message || '' ) ) {
				store.toast( 'The request timed out on the server — check via FTP/file manager whether it completed.', 'error' );
			} else {
				store.toast( e.message, 'error' );
			}
		} finally {
			setBusy( '' );
			loadInv();
			loadBackups();
		}
	};

	const run = async ( endpoint, body, key, okMsg ) => {
		setBusy( key );
		try {
			const res = await api.post( endpoint, body );
			store.toast( res.message || okMsg, 'success' );
			return res;
		} catch ( e ) {
			store.toast( e.message, 'error' );
			return null;
		} finally {
			setBusy( '' );
		}
	};

	const repairCore = async () => {
		if (
			! window.confirm(
				'Reinstall clean WordPress core for the running version? Modified core files are restored and malware-dropped files inside wp-admin/ and wp-includes/ are removed. wp-content and wp-config.php are never touched.'
			)
		) {
			return;
		}
		const res = await run( '/incident/repair-core', {}, 'core', 'Core repaired.' );
		if ( res ) {
			setCoreResult( res );
		}
	};

	const repairPlugin = ( slug ) => {
		if ( ! window.confirm( `Reinstall a clean copy of "${ slug }" for its installed version? It runs in the background with live progress, and the current folder is backed up first.` ) ) {
			return;
		}
		setRepairingSlug( slug );
		startJob( '/incident/repair-plugin', { slug }, `Reinstalling “${ slug }”` );
	};

	const fixFile = async ( finding_id, path ) => {
		if ( ! window.confirm( 'Attempt to strip injected code from this file? The original is backed up and automatically restored if the site breaks.' ) ) {
			return;
		}
		const res = await run( '/incident/fix-file', { finding_id, path }, 'fx:' + ( finding_id || path ), 'File fixed.' );
		if ( res ) {
			loadInv();
			loadBackups();
		}
	};

	const restoreBackup = async ( id ) => {
		if ( ! window.confirm( 'Restore this backup over the current files?' ) ) {
			return;
		}
		const res = await run( '/incident/restore-backup', { id }, 'rb:' + id, 'Backup restored.' );
		if ( res ) {
			loadInv();
			loadBackups();
		}
	};

	const deleteBackup = async ( id ) => {
		if ( ! window.confirm( 'Delete this backup permanently? You will no longer be able to undo the repair it belongs to.' ) ) {
			return;
		}
		setBusy( 'del:' + id );
		try {
			await api.post( '/incident/delete-backup', { id } );
			store.toast( 'Backup deleted.', 'success' );
			loadBackups();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const clearBackups = () => {
		if ( ! window.confirm( 'Delete ALL repair backups? This frees disk space but removes your ability to undo past reinstalls/fixes. Active threats are not affected.' ) ) {
			return;
		}
		startJob( '/incident/clear-backups', {}, 'Clearing all repair backups' );
	};

	// Show the "run now" fallback once a queued job has clearly not started (cron not firing).
	const jobStale = jobSnap && jobSnap.status === 'queued' &&
		( Math.floor( Date.now() / 1000 ) - ( jobSnap.created || 0 ) ) > 15;

	return h(
		Fragment,
		null,

		/* ---- Self-healing guarantee ---- */
		h( 'p', { className: 'ts-notice ts-notice--success', style: { marginBottom: '16px' } },
			'🛡️ ',
			h( 'strong', null, 'Repairs watch themselves: ' ),
			'if a reinstall or file fix ever causes a fatal error, it auto-reverts from the backup it made before starting — you don’t have to notice and undo it yourself.'
		),

		/* ---- Live job progress (plugin reinstall, clear backups) ---- */
		job && h(
			Card,
			{ title: job.title },
			h( JobProgress, { job: jobSnap, title: job.title } ),
			jobStale && job.retry && h(
				'div',
				{ style: { marginTop: '10px' } },
				h( 'p', { className: 'ts-hint', style: { margin: '0 0 8px' } },
					'The background task hasn’t started — your host may not run WordPress cron automatically. You can run it now instead (the page will wait until it finishes).'
				),
				h( Button, { variant: 'default', onClick: runSyncFallback }, 'Run now instead' )
			)
		),

		/* ---- Core ---- */
		h(
			Card,
			{ title: 'WordPress core' },
			h(
				'p',
				null,
				'Reinstall a verified-clean copy of core for the exact version this site runs. Restores tampered files and removes malware-dropped files inside the core directories.'
			),
			h(
				'div',
				{ className: 'ts-actions-row' },
				h(
					Button,
					{ variant: 'primary', disabled: !! busy, onClick: repairCore },
					busy === 'core' ? 'Reinstalling…' : 'Reinstall clean core'
				)
			),
			coreResult && h( CoreSummary, { result: coreResult } )
		),

		/* ---- Repairable plugins ---- */
		h(
			Card,
			{
				title: 'Plugins from WordPress.org',
				actions: inv ? h( Badge, { tone: 'neutral' }, ( inv.repairable || [] ).length ) : null,
			},
			! inv
				? ( invError ? h( LoadError, { message: invError, onRetry: loadInv } ) : h( Spinner, null ) )
				: ( inv.repairable || [] ).length === 0
				? h( EmptyState, { icon: '🧩', title: 'None', hint: 'No WordPress.org plugins detected.' } )
				: h( RepairablePlugins, {
						rows: inv.repairable,
						busy: busy || ( job ? 'job' : '' ),
						activeSlug: repairingSlug,
						onAction: repairPlugin,
						query: pluginQuery,
						onQuery: setPluginQuery,
				  } )
		),

		/* ---- Manual / premium ---- */
		h(
			Card,
			{
				title: 'Premium / custom plugins (manual reinstall)',
				actions: inv ? h( Badge, { tone: 'warning' }, ( inv.unrepairable || [] ).length ) : null,
			},
			! inv
				? ( invError ? h( LoadError, { message: invError, onRetry: loadInv } ) : h( Spinner, null ) )
				: ( inv.unrepairable || [] ).length === 0
				? h( EmptyState, { icon: '🗂️', title: 'None', hint: 'Every installed plugin can be auto-repaired.' } )
				: h(
						Fragment,
						null,
						h(
							'p',
							{ className: 'ts-hint' },
							'These have no public clean source. Reinstall them from your own copy. If a specific file is infected, you can attempt an in-place fix — the original is backed up and auto-restored on failure.'
						),
						h(
							'div',
							null,
							inv.unrepairable.map( ( p ) =>
								h( ManualRow, { key: p.slug + p.file, plugin: p, busy, onFix: fixFile } )
							)
						)
				  )
		),

		/* ---- Backups ---- */
		h(
			Card,
			{
				title: 'Repair backups',
				actions: h( Fragment, null,
					summary && summary.count > 0 && h( 'span', { className: 'ts-muted', style: { marginRight: '8px', fontSize: '12px' } }, fmtBytes( summary.bytes ) ),
					backups && backups.length > 0 && h( Button, { variant: 'danger', disabled: !! busy || !! job, onClick: clearBackups }, 'Clear all' ),
					' ',
					backups ? h( Badge, { tone: backups.length ? 'neutral' : 'success' }, backups.length ) : null
				),
			},
			h( 'p', { className: 'ts-hint' },
				'These are automatic safety snapshots taken right before a reinstall or file fix so the change can be undone. ',
				'Only the most recent snapshot of each target is kept; older ones are removed automatically.'
			),
			summary && summary.over_threshold && h( 'p', { className: 'ts-notice ts-notice--warning', style: { display: 'flex', alignItems: 'center', gap: '8px' } },
				h( Badge, { tone: 'warning' }, 'Storage' ),
				h( 'span', null, `Repair backups are using ${ fmtBytes( summary.bytes ) } (over the ${ summary.threshold_human } reminder threshold). Consider clearing them to free space.` )
			),
			! backups
				? ( backupsError ? h( LoadError, { message: backupsError, onRetry: loadBackups } ) : h( Spinner, null ) )
				: backups.length === 0
				? h( EmptyState, { icon: '💾', title: 'No backups', hint: 'Backups appear here after a plugin reinstall or file fix.' } )
				: h( RepairBackupsTable, {
						backups, busy, job, query: backupQuery, onQuery: setBackupQuery,
						onRestore: restoreBackup, onDelete: deleteBackup,
				  } )
		)
	);
}

/** Repair backups table with search + client-side pagination (this list is unbounded until cleared). */
function RepairBackupsTable( { backups, busy, job, query, onQuery, onRestore, onDelete } ) {
	const filtered = backups.filter( ( b ) => matchesQuery( b, query, [ 'label', 'type', 'target' ] ) );
	const { pageItems, pager } = usePaged( filtered, 25 );

	return h( Fragment, null,
		backups.length > 5 && h( 'div', { className: 'ts-toolbar', style: { margin: '0 0 12px' } },
			h( ListSearch, { value: query, onChange: onQuery, placeholder: 'Search label, type, or target…' } )
		),
		filtered.length === 0
			? h( EmptyState, { icon: '🔍', title: 'No matching backups', hint: 'Try a different search term.' } )
			: h(
					'table',
					{ className: 'ts-table' },
					h(
						'thead',
						null,
						h(
							'tr',
							null,
							h( 'th', null, 'What' ),
							h( 'th', null, 'Type' ),
							h( 'th', null, 'Size' ),
							h( 'th', null, 'Target' ),
							h( 'th', null, 'When' ),
							h( 'th', null, 'Actions' )
						)
					),
					h(
						'tbody',
						null,
						pageItems.map( ( b ) =>
							h(
								'tr',
								{ key: b.id },
								h( 'td', null, b.label ),
								h( 'td', null, b.type ),
								h( 'td', null, fmtBytes( b.bytes ) ),
								h( 'td', { className: 'ts-uri', title: b.target }, b.target ),
								h( 'td', null, b.created ),
								h(
									'td',
									null,
									h(
										Button,
										{ variant: 'ghost', disabled: !! busy || !! job, onClick: () => onRestore( b.id ) },
										busy === 'rb:' + b.id ? 'Restoring…' : 'Restore'
									),
									' ',
									h(
										Button,
										{ variant: 'danger', disabled: !! busy || !! job, onClick: () => onDelete( b.id ) },
										busy === 'del:' + b.id ? 'Deleting…' : 'Delete'
									)
								)
							)
						)
					)
			  ),
		pager
	);
}

function CoreSummary( { result } ) {
	return h(
		'ul',
		{ className: 'ts-repair-summary' },
		h( 'li', null, `Restored: ${ ( result.replaced || [] ).length }` ),
		h( 'li', null, `Removed: ${ ( result.removed || [] ).length }` ),
		h( 'li', null, `Failed: ${ ( result.failed || [] ).length }` ),
		( result.reported_extras || [] ).length > 0 &&
			h(
				'li',
				null,
				`Review (web-root extras, not deleted): ${ ( result.reported_extras || [] ).join( ', ' ) }`
			)
	);
}

/** Repairable-plugins list with search + client-side pagination (grows with the site's plugin count). */
function RepairablePlugins( { rows, busy, activeSlug, onAction, query, onQuery } ) {
	const filtered = rows.filter( ( p ) => matchesQuery( p, query, [ 'name', 'slug' ] ) );
	const { pageItems, pager } = usePaged( filtered, 25 );

	return h( Fragment, null,
		h( ProGate, {
			feature: 'incident.bulk_repair',
			title: 'Reinstall all flagged plugins at once',
			bullets: [ 'One background job for every WordPress.org plugin (or a selection)', 'Each plugin backed up first, site health-checked between steps' ],
		} ),
		rows.length > 5 && h( 'div', { className: 'ts-toolbar', style: { margin: '0 0 12px' } },
			h( ListSearch, { value: query, onChange: onQuery, placeholder: 'Search plugin name or slug…' } )
		),
		filtered.length === 0
			? h( EmptyState, { icon: '🔍', title: 'No matching plugins', hint: 'Try a different search term.' } )
			: h( PluginTable, {
					rows: pageItems, busy, activeSlug,
					actionLabel: 'Reinstall clean', onAction,
			  } ),
		pager
	);
}

function PluginTable( { rows, busy, activeSlug, actionLabel, onAction } ) {
	return h(
		'table',
		{ className: 'ts-table' },
		h(
			'thead',
			null,
			h(
				'tr',
				null,
				h( 'th', null, 'Plugin' ),
				h( 'th', null, 'Version' ),
				h( 'th', null, 'Issues' ),
				h( 'th', null, 'Actions' )
			)
		),
		h(
			'tbody',
			null,
			rows.map( ( p ) =>
				h(
					'tr',
					{ key: p.slug + p.file },
					h( 'td', null, p.name, ! p.active && h( 'span', { className: 'ts-muted' }, ' (inactive)' ) ),
					h( 'td', null, p.version ),
					h( 'td', null, p.findings > 0 ? h( Badge, { tone: 'warning' }, p.findings ) : h( Badge, { tone: 'success' }, 'clean' ) ),
					h(
						'td',
						null,
						h(
							Button,
							{ variant: 'primary', disabled: !! busy, onClick: () => onAction( p.slug ) },
							activeSlug === p.slug ? 'Working…' : actionLabel
						)
					)
				)
			)
		)
	);
}

function ManualRow( { plugin, busy, onFix } ) {
	const issues = plugin.issues || [];
	return h(
		'div',
		{ className: 'ts-manual-row' },
		h(
			'div',
			{ className: 'ts-manual-row__head' },
			h( 'strong', null, plugin.name ),
			' ',
			h( 'span', { className: 'ts-muted' }, plugin.version ),
			' ',
			plugin.findings > 0
				? h( Badge, { tone: 'warning' }, plugin.findings + ' issue(s)' )
				: h( Badge, { tone: 'success' }, 'clean' )
		),
		h( 'div', { className: 'ts-hint' }, plugin.reason ),
		issues.length > 0 &&
			h(
				'ul',
				{ className: 'ts-issue-list' },
				issues.map( ( f ) =>
					h(
						'li',
						{ key: f.id },
						h( 'span', { className: 'ts-uri', title: f.path }, f.path ),
						' ',
						h( 'span', { className: 'ts-muted' }, f.rule ),
						' ',
						h(
							Button,
							{ variant: 'ghost', disabled: !! busy, onClick: () => onFix( f.id, f.path ) },
							busy === 'fx:' + f.id ? 'Fixing…' : 'Try to fix'
						)
					)
				)
			)
	);
}
