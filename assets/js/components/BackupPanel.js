/**
 * Backup & Recovery panel — create files/full backups, restore or delete them, and manage the
 * standalone recovery token used to restore when the site itself is down.
 */
import { h, useState, useEffect, Fragment } from '../el.js';
import { api, saveFile } from '../api.js';
import { Card, Button, Badge, Spinner, EmptyState, Toggle, Modal } from './ui.js';
import { ProGate } from './ProGate.js';
import { useStore } from '../store.js';
import { useJobPoller, JobProgress } from './JobProgress.js';
import { usePaged, ListSearch, matchesQuery } from './PaginatedList.js';

function fmtBytes( n ) {
	n = Number( n ) || 0;
	if ( n < 1024 ) return n + ' B';
	if ( n < 1048576 ) return ( n / 1024 ).toFixed( 1 ) + ' KB';
	if ( n < 1073741824 ) return ( n / 1048576 ).toFixed( 1 ) + ' MB';
	return ( n / 1073741824 ).toFixed( 2 ) + ' GB';
}

export function BackupPanel() {
	const store = useStore();
	const [ items, setItems ] = useState( null );
	const [ loadError, setLoadError ] = useState( null );
	const [ backupQuery, setBackupQuery ] = useState( '' );
	const [ recovery, setRecovery ] = useState( { enabled: false } );
	const [ busy, setBusy ] = useState( '' );
	const [ scope, setScope ] = useState( 'full' );
	const [ token, setToken ] = useState( null );
	// Schedule (auto-backup) state — loaded from the server (backup.schedule), not assumed.
	const [ schedule, setSchedule ] = useState( null ); // null until loaded; 'none' | 'weekly' | 'daily'
	// Standalone recovery guided-flow state.
	const [ recoveryStep, setRecoveryStep ] = useState( 'token' ); // 'token' | 'active'
	// Async backup job tracking.
	const [ backupJobId, setBackupJobId ] = useState( null );
	const [ backupSettingsModalOpen, setBackupSettingsModalOpen ] = useState( false );
	const backupJob = useJobPoller( backupJobId, {
		onDone: ( j ) => {
			setBackupJobId( null );
			load();
			const size = j.result && j.result.zip_bytes ? ' (' + Math.round( j.result.zip_bytes / 1048576 * 10 ) / 10 + ' MB)' : '';
			store.toast( 'Backup complete' + size + '.', 'success' );
		},
		onError: ( j ) => {
			setBackupJobId( null );
			store.toast( j.error || 'Backup failed.', 'error' );
		},
	} );

	// On failure `items` MUST stay null (not become []) so the panel shows a retryable error
	// instead of getting stuck on the loading spinner forever or claiming "no backups exist".
	const load = () => api.get( '/backups' ).then( ( d ) => {
		setItems( d.items || [] );
		setRecovery( d.recovery || { enabled: false } );
		setLoadError( null );
	} ).catch( ( e ) => {
		store.toast( e.message, 'error' );
		setLoadError( e.message || 'Failed to load backups.' );
	} );

	// Load the persisted auto-backup cadence so the toggles reflect real server state instead
	// of a hardcoded default.
	const loadSchedule = () => api.get( '/settings' )
		.then( ( d ) => setSchedule( ( d && d.backup && d.backup.schedule ) || 'none' ) )
		.catch( () => setSchedule( 'none' ) );

	useEffect( () => { load(); loadSchedule(); }, [] );

	// If recovery was already enabled in a previous session, jump straight to the "active" step
	// (unless we're mid-flow showing a freshly minted token).
	useEffect( () => {
		if ( recovery.enabled && ! token ) {
			setRecoveryStep( 'active' );
		}
	}, [ recovery.enabled ] );

	const create = async () => {
		if ( backupJobId ) return; // already running
		setBusy( 'create' );
		try {
			// Server returns {job_id, status:'queued'} immediately — actual backup runs in the
			// background via WP-Cron. The useJobPoller hook polls /jobs/{id} every 2 s.
			const res = await api.post( '/backups/create', { scope } );
			setBackupJobId( res.job_id );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const restore = async ( id, withDb ) => {
		if ( ! window.confirm( 'Restore this backup? It overwrites current files' + ( withDb ? ' and the database' : '' ) + '. This cannot be undone from here.' ) ) return;
		setBusy( 'r:' + id );
		try {
			const res = await api.post( '/backups/restore', { id, db: withDb } );
			store.toast( res.message || 'Restore complete.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const del = async ( id ) => {
		if ( ! window.confirm( 'Delete this backup permanently?' ) ) return;
		setBusy( 'd:' + id );
		try {
			await api.post( '/backups/delete', { id } );
			store.toast( 'Backup deleted.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const setRecoveryEnabled = async ( enable ) => {
		if ( enable && ! window.confirm( 'Enable the standalone recovery endpoint? It lets anyone with the one-time token restore a backup even if WordPress is down. Keep the token secret.' ) ) return;
		if ( ! enable && ! window.confirm( 'Disable standalone recovery? The current token will stop working.' ) ) return;
		setBusy( 'recovery' );
		try {
			const res = await api.post( '/backups/recovery', { enable } );
			if ( enable && res.token ) {
				setToken( { token: res.token } );
			} else {
				setToken( null );
			}
			store.toast( enable ? 'Recovery enabled.' : 'Recovery disabled.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Persist the auto-backup cadence to the real backup.schedule setting. Optimistic, with a
	// rollback to the previous value if the save fails (otherwise the UI would show a cadence
	// the server never accepted).
	const saveSchedule = async ( nextFreq ) => {
		const prev = schedule;
		setSchedule( nextFreq );
		setBusy( 'schedule' );
		try {
			await api.post( '/settings/backup', { schedule: nextFreq } );
			store.toast( nextFreq === 'none' ? 'Automatic backups turned off.' : 'Backup schedule saved.', 'success' );
		} catch ( e ) {
			setSchedule( prev );
			store.toast( e.message || 'Could not save schedule.', 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Enable standalone recovery and surface the one-time token. There is a single real
	// endpoint for this — POST /backups/recovery { enable: true } (recovery_set()) already
	// returns the fresh plaintext token. (The former /backups/recovery/token +
	// /backups/recovery/enable calls never existed server-side, so this guided flow could
	// never actually turn recovery on.)
	const generateToken = async () => {
		setBusy( 'recovery' );
		try {
			const res = await api.post( '/backups/recovery', { enable: true } );
			if ( res && res.token ) {
				setToken( { token: res.token } );
			}
			store.toast( 'Recovery token generated. Save it now.', 'success' );
			load();
		} catch ( e ) {
			store.toast( e.message || 'Could not generate token.', 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// The recovery tool is never written to the server by the plugin: the dashboard generates a
	// copy with this site's paths built in and the operator uploads it themselves. It can be
	// re-downloaded any time (e.g. after losing the saved copy) while recovery stays enabled.
	const downloadRecoveryTool = async () => {
		setBusy( 'recovery-download' );
		try {
			const file = await api.get( '/backups/recovery/download' );
			saveFile( file.filename, file.content, file.mime || 'application/octet-stream' );
		} catch ( e ) {
			store.toast( e.message || 'Could not download the recovery tool.', 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Finalize the guided recovery flow once the operator confirms they saved the token.
	const activateRecovery = () => {
		setRecoveryStep( 'active' );
		store.toast( 'Standalone recovery is active.', 'success' );
	};

	// usePaged() must run on every render (Rules of Hooks) — compute it before the early
	// returns below, using an empty list while backups haven't loaded yet.
	const filteredBackups = ( items || [] ).filter( ( m ) => matchesQuery( m, backupQuery, [ 'created' ] ) );
	const { pageItems: pagedBackups, pager: backupsPager } = usePaged( filteredBackups, 25 );

	if ( ! items ) {
		if ( loadError ) {
			return h( Card, { title: 'Backups' },
				h( 'p', { className: 'ts-error' }, '⚠️ Could not load backups: ' + loadError ),
				h( Button, { variant: 'primary', onClick: load }, 'Retry' )
			);
		}
		return h( 'div', { className: 'ts-loading' }, h( Spinner, null ) );
	}

	return h( Fragment, null,
		h( Card, { title: 'Create a backup' },
			// While a backup job is running, replace the button row with inline live progress.
			backupJobId
				? h( JobProgress, { job: backupJob, title: scope === 'full' ? 'Backing up files + database…' : 'Backing up files…' } )
				: h( Fragment, null,
						h( 'div', { className: 'ts-actions-row' },
							h( 'select', { id: 'ts-backup-scope', name: 'backup_scope', value: scope, disabled: !! busy, onChange: ( e ) => setScope( e.target.value ) },
								h( 'option', { value: 'full' }, 'Files + database' ),
								h( 'option', { value: 'files' }, 'Files only' )
							),
							h( Button, { variant: 'primary', disabled: !! busy, onClick: create }, busy === 'create' ? 'Starting…' : 'Create backup' )
						),
						h( 'p', { className: 'ts-muted', style: { fontSize: '12px', marginTop: '8px' } },
							'Runs in the background — you can keep using the dashboard while the backup is in progress. How many backups are kept is set by “Max Backups” under Settings → Backup & Recovery.'
						)
				  )
		),

		h( Card, {
			title: '⚙️ Backup Settings',
			actions: h( Button, { variant: 'primary', onClick: () => setBackupSettingsModalOpen( true ) }, 'Manage settings' ),
		},
			h( 'p', { className: 'ts-muted', style: { marginTop: 0, marginBottom: 0 } },
				'Automatic backup schedule and standalone recovery.'
			)
		),

		h( Modal, {
			open: backupSettingsModalOpen,
			onClose: () => setBackupSettingsModalOpen( false ),
			title: 'Backup Settings',
			icon: '⚙️',
			size: 'lg',
		},

		/* ---- Schedule (auto-backup) ---- */
		h( Card, { title: 'Schedule' },
			null === schedule
				? h( 'div', { className: 'ts-loading' }, h( Spinner, null ) )
				: h( Fragment, null,
						h( 'div', { className: 'ts-schedule-row' },
							h( Toggle, {
								checked: schedule === 'weekly' || schedule === 'daily',
								disabled: busy === 'schedule',
								label: 'Automatic backup',
								onChange: ( on ) => saveSchedule( on ? 'weekly' : 'none' ),
							} )
						),
						( schedule === 'weekly' || schedule === 'daily' ) && h( 'div', { className: 'ts-schedule-row' },
							h( Toggle, {
								checked: schedule === 'daily',
								disabled: busy === 'schedule',
								label: 'Run daily instead of weekly',
								onChange: ( on ) => saveSchedule( on ? 'daily' : 'weekly' ),
							} )
						)
				  )
		),

		h( ProGate, {
			feature: 'backup.woo_delta',
			title: 'WooCommerce-aware backups',
			description: 'Captures every order, customer, product and stock change between scheduled backups and replays them on restore.',
			bullets: [
				'No WooCommerce data lost between backups',
				'Covers orders, customers, products, stock and coupons',
				'Configurable 7-day delta retention window',
			],
		} ),

		token && h( Card, { title: '⚠️ Save your recovery token now' },
			h( 'p', null, 'This token is shown ', h( 'strong', null, 'only once' ), '. Store it somewhere safe — the recovery tool asks for it if the site goes down.' ),
			h( 'p', null, 'Token: ', h( 'code', { style: { userSelect: 'all', wordBreak: 'break-all', background: 'var(--ts-bg)', padding: '4px 8px', borderRadius: '4px' } }, token.token ) ),
			h( Button, { variant: 'default', onClick: () => setToken( null ) }, 'I have saved it' )
		),

		h( Card, {
			title: 'Standalone recovery',
			actions: ( recovery.enabled || recoveryStep === 'active' )
				? h( Button, {
						variant: 'danger',
						disabled: busy === 'recovery',
						onClick: () => { setRecoveryStep( 'token' ); setRecoveryEnabled( false ); },
					}, 'Disable' )
				: null,
		},
			h( 'p', { className: 'ts-muted', style: { fontSize: '13px' } },
				'A small, token-protected recovery tool can restore a backup even if WordPress cannot load. You download it here and upload it to your server yourself. Only a hashed token is stored; failed attempts are rate-limited and locked out.'
			),

			/* Step A — no backups yet. */
			items.length === 0 && ! recovery.enabled && recoveryStep !== 'active' && h( 'div', { className: 'ts-recovery-step' },
				h( 'p', null, 'You need at least one backup before enabling standalone recovery.' ),
				h( Button, { variant: 'primary', disabled: !! busy, onClick: create }, busy === 'create' ? 'Creating…' : 'Create a backup now' )
			),

			/* Step B — generate & display token. */
			items.length > 0 && ! ( recovery.enabled && recoveryStep === 'active' ) && recoveryStep !== 'active' && h( 'div', { className: 'ts-recovery-step' },
				h( 'p', null, 'Status: ', recovery.enabled ? h( Badge, { tone: 'success' }, 'Enabled' ) : h( Badge, { tone: 'neutral' }, 'Not yet active' ) ),
				! token && h( Button, { variant: 'primary', disabled: busy === 'recovery', onClick: generateToken },
					busy === 'recovery' ? 'Generating…' : 'Generate recovery token'
				),
				token && h( Fragment, null,
					h( 'p', { style: { margin: '12px 0 4px', fontWeight: '600' } }, 'Your recovery token:' ),
					h( 'div', { className: 'ts-token-box' },
						h( 'code', { style: { userSelect: 'all', wordBreak: 'break-all' } }, token.token ),
						h( Button, { variant: 'secondary', onClick: () => {
							try { navigator.clipboard.writeText( token.token ); store.toast( 'Token copied.', 'success' ); } catch ( e ) { store.toast( 'Copy failed — select it manually.', 'error' ); }
						} }, 'Copy' )
					),
					h( Button, { variant: 'primary', style: { marginTop: '12px' }, onClick: activateRecovery },
						'I have saved the token — Activate recovery'
					)
				)
			),

			/* Step C — recovery active. */
			recoveryStep === 'active' && h( 'div', { className: 'ts-recovery-step' },
				h( 'p', null, h( Badge, { tone: 'success' }, 'Active' ), ' Standalone recovery is active.' ),
				h( 'ol', { className: 'ts-muted', style: { fontSize: '13px', paddingLeft: '18px' } },
					h( 'li', null, 'Download the recovery tool below — it is made for this site.' ),
					h( 'li', null, 'Upload it to your server now, while the site works (for example to the site’s root folder), using FTP or your host’s file manager. Any file name works.' ),
					h( 'li', null, 'If the site ever goes down, open that file’s address in your browser and enter your token.' )
				),
				h( 'button', {
					type: 'button',
					className: 'ts-btn',
					style: { marginRight: '10px' },
					disabled: busy === 'recovery-download',
					onClick: downloadRecoveryTool,
				}, busy === 'recovery-download' ? 'Preparing…' : '⬇ Download recovery tool' ),
				h( 'button', {
					type: 'button',
					className: 'ts-linkbtn',
					onClick: () => { setRecoveryStep( 'token' ); setToken( null ); },
				}, 'Regenerate token' )
			)
		),

		h( ProGate, {
			feature: 'backup.staging',
			title: 'Test restores on a staging copy',
			description: 'Restore a backup into an isolated staging copy of the site and check it before touching the live site.',
			bullets: [ 'Disposable staging environment per backup', 'Access-token protected, expires automatically' ],
		} )
		),

		h( Card, { title: 'Backups', actions: h( Badge, { tone: items.length ? 'neutral' : 'success' }, items.length ) },
			items.length === 0
				? h( EmptyState, { icon: '💾', title: 'No backups yet', hint: 'Create your first backup above.' } )
				: h( Fragment, null,
						items.length > 5 && h( 'div', { className: 'ts-toolbar', style: { margin: '0 0 12px' } },
							h( ListSearch, { value: backupQuery, onChange: setBackupQuery, placeholder: 'Search by date…' } )
						),
						filteredBackups.length === 0
							? h( EmptyState, { icon: '🔍', title: 'No matching backups', hint: 'Try a different search term.' } )
							: h( 'table', { className: 'ts-table' },
									h( 'thead', null, h( 'tr', null,
										h( 'th', null, 'Created' ), h( 'th', null, 'Scope' ), h( 'th', null, 'Files' ),
										h( 'th', null, 'Size' ), h( 'th', null, 'Actions' )
									) ),
									h( 'tbody', null, pagedBackups.map( ( m ) =>
										h( 'tr', { key: m.id },
											h( 'td', null, m.created ),
											h( 'td', null, h( Badge, { tone: m.db_included ? 'warning' : 'neutral' }, m.db_included ? 'Files + DB' : 'Files' ) ),
											h( 'td', null, m.files ),
											h( 'td', null, fmtBytes( ( m.zip_bytes || 0 ) + ( m.db_bytes || 0 ) ) ),
											h( 'td', null,
												h( Button, { variant: 'default', disabled: !! busy, onClick: () => restore( m.id, false ) }, busy === 'r:' + m.id ? 'Restoring…' : 'Restore files' ),
												' ',
												m.db_included && h( Button, { variant: 'primary', disabled: !! busy, onClick: () => restore( m.id, true ) }, 'Restore files + DB' ),
												' ',
												h( Button, { variant: 'danger', disabled: !! busy, onClick: () => del( m.id ) }, 'Delete' )
											)
										)
									) )
							  ),
						backupsPager
				  )
		)
	);
}
