/**
 * Scanner panel — runs batched malware scans, file-integrity checks, and shows findings.
 *
 * Findings are remediation-aware: core files collapse into a single "Reinstall core" action
 * and WordPress.org plugin files into a per-plugin "Reinstall" (because the correct fix there
 * is a clean reinstall, not editing individual files), while premium/custom/theme code offers
 * a conservative, backed-up per-file "Fix". Quarantine remains for true one-off junk.
 */
import { h, useState, useEffect, useRef, Fragment } from '../el.js';
import { api } from '../api.js';
import { Card, Button, Badge, EmptyState, LoadError, severityTone, InfoTip } from './ui.js';
import { threatMeta } from '../events.js';
import { useStore } from '../store.js';
import { CodeInspector } from './CodeInspector.js';
import { useJobPoller, JobProgress } from './JobProgress.js';
import { usePaged } from './PaginatedList.js';
import { ProGate } from './ProGate.js';

export function ScanPanel( { defaultTab } ) {
	const store = useStore();
	const [ tab, setTab ] = useState( defaultTab || 'scanner' ); // 'scanner' | 'integrity' | 'combined'
	const [ type, setType ] = useState( 'full' );
	const [ progress, setProgress ] = useState( null );
	const [ running, setRunning ] = useState( false );
	const [ findings, setFindings ] = useState( [] );
	const [ findingsError, setFindingsError ] = useState( null );
	const [ findingsQuery, setFindingsQuery ] = useState( '' );
	const [ findingsSeverity, setFindingsSeverity ] = useState( '' ); // '' | 'critical' | 'warning' | 'notice'
	const [ triage, setTriage ] = useState( null );
	const [ integrity, setIntegrity ] = useState( null );
	const [ busy, setBusy ] = useState( '' );
	const [ inspecting, setInspecting ] = useState( null );
	const [ recent, setRecent ] = useState( [] );
	const [ refreshing, setRefreshing ] = useState( false );

	// Cleared on unmount so the self-rescheduling drive() loop and its
	// setState calls stop instead of running forever (and warning) after the panel is gone.
	const alive = useRef( true );

	// Background reinstall job (single plugin or bulk) — async-first via the JobStore poller.
	const [ repairJob, setRepairJob ] = useState( null ); // { id, title }
	const repairSnap = useJobPoller( repairJob && repairJob.id, {
		onDone: ( j ) => {
			store.toast( ( j.result && j.result.message ) || j.step || 'Reinstall complete.', 'success' );
			setRepairJob( null );
			refresh();
		},
		onError: ( j ) => {
			store.toast( j.error || 'Reinstall failed.', 'error' );
			setRepairJob( null );
			refresh();
		},
	} );

	const loadHistory = () => api.get( '/scanner/history' ).then( ( d ) => setRecent( d.items || [] ) ).catch( () => {} );
	// Must not silently swallow a failure here: this drives the main "Open findings" list, and a
	// failed request falling through to the empty-state ("No open findings — nothing suspicious
	// detected") would be a false all-clear on the malware scanner's primary view.
	const loadFindings = () => api.get( '/scan/findings', { status: 'open' } ).then( ( d ) => {
		setFindings( d.items || [] );
		setFindingsError( null );
	} ).catch( ( e ) => setFindingsError( e.message || 'Failed to load findings.' ) );
	const loadTriage = () => api.get( '/incident/triage' ).then( setTriage ).catch( () => setTriage( null ) );
	const refresh = () => { loadFindings(); loadTriage(); loadHistory(); };

	useEffect( () => {
		refresh();
		// On entering the panel, show the latest scan state and resume driving it if a scan
		// is still running (e.g. it was started, then the panel/tab was left and came back).
		api.get( '/scan/progress' ).then( ( p ) => {
			setProgress( p );
			if ( p && p.status === 'running' && p.scan_id ) {
				drive( p.scan_id );
			}
		} ).catch( () => {} );

		alive.current = true;
		return () => { alive.current = false; };
	}, [] );

	// Drive a scan's batches to completion. A page-global guard ensures only one driver runs
	// at a time even if several panels/effects try to resume the same scan; the server-side
	// cron driver is the fallback when no tab is open.
	const drive = async ( scanId ) => {
		// Another driver (this or another mount) already owns the loop — don't start a second,
		// but DON'T leave this instance's button stuck on "running" either: clear it, since the
		// owning driver updates progress via the shared /scan/progress the effect reads.
		if ( window.__loyalsecDriving ) {
			setRunning( false );
			return;
		}
		window.__loyalsecDriving = scanId;
		setRunning( true );
		try {
			let state = { scan_id: scanId, status: 'running' };
			// Stop the batch loop the moment the panel unmounts — the server-side cron driver
			// finishes the scan, so there's no need to keep POSTing after navigation.
			while ( state.status === 'running' && alive.current ) {
				state = await api.post( '/scan/batch', { scan_id: scanId } );
				if ( ! alive.current ) break;
				setProgress( state );
			}
			if ( state.status !== 'running' ) {
				// "Run your first scan" is a setup step: let the setup banner re-check.
				window.dispatchEvent( new Event( 'loyalsec:setup-changed' ) );
			}
			if ( alive.current && state.status !== 'running' ) {
				store.toast( `Scan complete — ${ state.findings } finding(s).`, state.findings ? 'warning' : 'success' );
				refresh();
			}
		} catch ( e ) {
			if ( alive.current ) store.toast( e.message, 'error' );
		} finally {
			if ( alive.current ) setRunning( false );
			window.__loyalsecDriving = null;
		}
	};

	const runScan = async () => {
		// Flip the button and show a starting message immediately — /scan/start builds the
		// file list before responding, which can take a second or two on a large site, and
		// without this the UI looks unresponsive between the click and the first progress tick.
		setRunning( true );
		setProgress( null );
		try {
			const start = await api.post( '/scan/start', { type } );
			setProgress( { scan_id: start.scan_id, status: 'running', total_files: start.total, scanned_files: 0, findings: 0 } );
			drive( start.scan_id );
		} catch ( e ) {
			store.toast( e.message, 'error' );
			setRunning( false );
		}
	};

	const runIntegrity = async () => {
		setBusy( 'integrity' );
		try {
			const res = await api.post( '/integrity/run', {} );
			setIntegrity( res );
			store.toast( `Integrity check done — ${ res.changed } change(s).`, res.changed ? 'warning' : 'success' );
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const snapshot = async () => {
		setBusy( 'snapshot' );
		try {
			const res = await api.post( '/integrity/snapshot', {} );
			store.toast( `Baseline recorded (${ res.recorded } files).`, 'success' );
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Finding-status actions (quarantine / ignore).
	const act = async ( finding, status ) => {
		try {
			if ( status === 'quarantined' ) {
				await api.post( '/quarantine/add', { finding_id: finding.id } );
				store.toast( 'File quarantined.', 'success' );
			} else {
				await api.post( '/scan/findings/status', { id: finding.id, status } );
				store.toast( 'Finding updated.', 'success' );
			}
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	// Dismiss all findings where the file no longer exists.
	const dismissStale = async () => {
		const stale = findings.filter( ( f ) => f.file_missing );
		if ( ! stale.length ) return;
		if ( ! window.confirm( `Mark ${ stale.length } stale finding(s) as ignored? These point to files that no longer exist on disk.` ) ) return;
		try {
			await Promise.all( stale.map( ( f ) => api.post( '/scan/findings/status', { id: f.id, status: 'ignored' } ) ) );
			store.toast( `${ stale.length } stale finding(s) dismissed.`, 'success' );
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		}
	};

	// Re-check every open finding without a full rescan: clears findings whose file is gone, now
	// matches an official WordPress.org release, or no longer matches the rule that flagged it.
	const refreshFindings = async () => {
		setRefreshing( true );
		try {
			const res = await api.post( '/scan/findings/refresh', {} );
			store.toast(
				`Rechecked ${ res.checked } open finding(s) — ${ res.resolved } no longer valid and cleared.`,
				res.resolved ? 'success' : 'info'
			);
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setRefreshing( false );
		}
	};

	// Bulk-clear the Open findings list. "Ignore all" is reversible (Ignored filter); "Whitelist
	// all" additionally suppresses those paths from future scans.
	const bulkClear = async ( action ) => {
		const msg = action === 'whitelist'
			? `Whitelist and clear all ${ findings.length } open finding(s)? Their files will be marked safe and skipped in future scans. Only do this if you trust them.`
			: `Ignore all ${ findings.length } open finding(s)? They move to the Ignored list and can be reviewed later.`;
		if ( ! window.confirm( msg ) ) return;
		setBusy( 'bulk:' + action );
		try {
			const res = await api.post( '/scan/findings/bulk', { action } );
			store.toast(
				action === 'whitelist'
					? `${ res.updated } cleared, ${ res.whitelisted } path(s) whitelisted.`
					: `${ res.updated } finding(s) ignored.`,
				'success'
			);
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Whitelist a single finding's path (mark a known false positive safe forever).
	const whitelistOne = async ( f ) => {
		if ( ! window.confirm( 'Mark this file as safe and skip it in future scans? Use this only for confirmed false positives.' ) ) return;
		setBusy( 'wl:' + f.id );
		try {
			await api.post( '/scan/whitelist', { value: f.path, type: 'path', finding_id: f.id } );
			store.toast( 'Whitelisted.', 'success' );
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Repair actions.
	const runRepair = async ( endpoint, body, key, okMsg ) => {
		if ( busy ) return;
		setBusy( key );
		try {
			const res = await api.post( endpoint, body );
			store.toast( ( res && res.message ) || okMsg, 'success' );
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	// Start a background reinstall job (single plugin or bulk). Async-first: the server returns a
	// job id we poll; if it ran inline we just refresh.
	const startRepairJob = async ( endpoint, body, title ) => {
		if ( repairJob ) return;
		// Disable the trigger button and show the "Starting…" progress row immediately —
		// JobProgress already renders that state for a null job snapshot — rather than leaving
		// the button looking inert while /incident/repair-* builds the job server-side.
		setRepairJob( { id: null, title } );
		try {
			const res = await api.post( endpoint, body );
			if ( res && res.job_id ) {
				setRepairJob( { id: res.job_id, title } );
				store.toast( title + ' — running in the background. You can keep working.', 'info' );
			} else {
				store.toast( ( res && res.message ) || 'Done.', 'success' );
				setRepairJob( null );
				refresh();
			}
		} catch ( e ) {
			setRepairJob( null );
			store.toast( e.message, 'error' );
		}
	};

	const reinstallCore = () => {
		if ( ! window.confirm( 'Reinstall clean WordPress core for the running version? This restores flagged core files and removes malware-dropped files in wp-admin/ and wp-includes/. wp-content and wp-config.php are untouched.' ) ) return;
		runRepair( '/incident/repair-core', {}, 'core', 'Core repaired.' );
	};
	const reinstallPlugin = ( slug ) => {
		if ( ! window.confirm( `Reinstall a clean copy of "${ slug }"? It runs in the background and the current folder is backed up first.` ) ) return;
		startRepairJob( '/incident/repair-plugin', { slug }, `Reinstalling “${ slug }”` );
	};
	// Verify a wp.org plugin against official checksums and clear false positives (no reinstall).
	// Ideal when a freshly installed plugin still shows flagged files.
	const verifyPlugin = async ( slug ) => {
		setBusy( 'vf:' + slug );
		try {
			const res = await api.post( '/incident/verify-plugin', { slug } );
			store.toast( res.message || 'Verified.', res.kept ? 'warning' : 'success' );
			refresh();
		} catch ( e ) {
			store.toast( e.message, 'error' );
		} finally {
			setBusy( '' );
		}
	};

	const removeFile = ( finding ) => {
		if ( ! window.confirm( 'Delete this file? A backup is kept (restorable from the Repair Center) and the site is automatically restored if the deletion breaks it.' ) ) return;
		runRepair( '/incident/remove-file', { finding_id: finding.id, path: finding.path }, 'rm:' + finding.id, 'File deleted.' );
	};
	const fixFile = ( finding ) => {
		if ( ! window.confirm( 'Attempt to strip the injected code from this file? The original is backed up and automatically restored if the site breaks.' ) ) return;
		runRepair( '/incident/fix-file', { finding_id: finding.id, path: finding.path }, 'fx:' + finding.id, 'File fixed.' );
	};

	// Build lookup sets from the triage groups.
	const coreIds = new Set( ( triage && triage.core && triage.core.ids ) || [] );
	const pluginById = new Map();
	( ( triage && triage.plugins ) || [] ).forEach( ( p ) =>
		( p.ids || [] ).forEach( ( id ) => pluginById.set( id, p ) )
	);

	const pct = progress && progress.total_files ? Math.round( ( progress.scanned_files / progress.total_files ) * 100 ) : 0;
	const staleCount = findings.filter( ( f ) => f.file_missing ).length;
	// Client-side filter over the already-fetched findings — a full scan can easily produce
	// 100+ rows with no way to jump to a specific file/rule, so search by path/rule/category/
	// snippet text plus an optional severity narrow.
	const visibleFindings = findings.filter( ( f ) => {
		if ( findingsSeverity && sevLabel( f.severity ) !== findingsSeverity ) return false;
		if ( ! findingsQuery ) return true;
		const q = findingsQuery.toLowerCase();
		return [ f.path, f.rule, f.category, f.snippet ].some( ( v ) => ( v || '' ).toLowerCase().includes( q ) );
	} );
	// Paginate: a full scan can produce hundreds of findings — render one page at a time.
	const { pageItems: pagedFindings, pager: findingsPager } = usePaged( visibleFindings, 25 );
	const wporgGroups = ( ( triage && triage.plugins ) || [] ).filter( ( p ) => p.on_wporg );
	const hasRecs = !! ( triage && ( ( triage.core && triage.core.count > 0 ) || wporgGroups.length ) );

	const showScanner   = tab === 'scanner'   || tab === 'combined';
	const showIntegrity = tab === 'integrity' || tab === 'combined';

	return h(
		Fragment,
		null,
		inspecting && h( CodeInspector, { finding: inspecting, onClose: () => setInspecting( null ), onChanged: refresh } ),

		/* ---- Tab bar -------------------------------------------------------- */
		h( 'div', { className: 'ts-tabbar ts-tabbar--toplevel', style: { marginBottom: '16px' } },
			[
				[ 'scanner',   '🔬 Malware Scanner' ],
				[ 'integrity', '🧬 Integrity Check'  ],
				[ 'combined',  '⚡ Combined'          ],
			].map( ( [ key, label ] ) =>
				h( 'button', {
					key,
					type: 'button',
					className: 'ts-tab' + ( tab === key ? ' ts-tab--active' : '' ),
					onClick: () => setTab( key ),
				}, label )
			)
		),

		showScanner && h(
			Card,
			{ title: 'Run a malware scan' },
			h( 'div', { className: 'ts-actions-row' },
				h( 'select', { id: 'ts-scan-type', name: 'scan_type', value: type, disabled: running, onChange: ( e ) => setType( e.target.value ) },
					h( 'option', { value: 'full' }, 'Full site' ),
					h( 'option', { value: 'content' }, 'wp-content' ),
					h( 'option', { value: 'uploads' }, 'Uploads only' ),
					h( 'option', { value: 'core' }, 'Core directories' )
				),
				h( Button, { variant: 'primary', disabled: running, onClick: runScan }, running ? 'Scanning…' : 'Start scan' ),
			),
			running && ! progress && h( 'div', { className: 'ts-job-progress', style: { marginTop: '12px' } },
				h( 'div', { className: 'ts-job-progress__footer' },
					h( 'span', { className: 'ts-spinner ts-spinner--sm', 'aria-hidden': 'true' } ),
					h( 'span', { className: 'ts-job-progress__step' }, 'Scanner is starting…' )
				)
			),
			running && progress && h( 'div', { className: 'ts-job-progress', style: { marginTop: '12px' } },
				h( 'div', { className: 'ts-job-progress__title' },
					progress.phase
						? 'Scanning ' + progress.phase + '…'
						: 'Scanning files…'
				),
				h( 'div', { className: 'ts-job-bar' },
					h( 'div', { className: 'ts-job-bar__fill', style: { width: pct + '%' } } )
				),
				h( 'div', { className: 'ts-job-progress__footer' },
					h( 'span', { className: 'ts-spinner ts-spinner--sm', 'aria-hidden': 'true' } ),
					h( 'span', { className: 'ts-job-progress__step' },
						( progress.scanned_files || 0 ).toLocaleString() + ' of ' +
						( progress.total_files   || '?' ).toLocaleString() + ' files scanned'
					),
					h( 'span', { className: 'ts-job-progress__pct' },
						( progress.findings || 0 ) + ' finding' + ( ( progress.findings || 0 ) === 1 ? '' : 's' )
					)
				)
			),
			! running && progress && progress.status && progress.status !== 'none' && progress.status !== 'running' && h( 'p', { className: 'ts-muted', style: { fontSize: '12px', marginTop: '8px' } },
				'Last scan: ' + ( progress.status === 'done' ? '✓ Complete' : progress.status ) +
				' · ' + ( progress.scanned_files || 0 ).toLocaleString() + ' files · ' +
				( progress.findings || 0 ) + ' finding(s)'
			)
		),

		/* ---- Integrity controls -------------------------------------------- */
		showIntegrity && h(
			Card,
			{ title: 'File Integrity Check' },
			h( 'p', null, 'Verify that WordPress core files, plugins, and theme files match the official checksums from WordPress.org. Use the baseline snapshot to detect drift in custom code, premium/unverifiable plugins, must-use plugins, and drop-ins (none of which WordPress.org publishes checksums for).' ),
			h( 'div', { className: 'ts-actions-row' },
				h( Button, { variant: 'primary', disabled: !! busy, onClick: runIntegrity }, busy === 'integrity' ? 'Checking…' : 'Run integrity check' ),
				h( Button, { variant: 'ghost', disabled: !! busy, onClick: snapshot, title: 'Record a theme / plugin / mu-plugin / drop-in baseline for drift detection' }, busy === 'snapshot' ? 'Recording…' : 'Snapshot baseline' )
			),
			// Nudge: drift detection for anything without an official checksum source (themes,
			// unverifiable/premium plugins, mu-plugins, drop-ins) only works once a baseline
			// exists. If a run reported any source without one, prompt the operator to snapshot.
			showIntegrity && integrity && [].concat( integrity.themes || [], integrity.mu || [], ( integrity.plugins && integrity.plugins.unverifiable ) || [] ).some( ( s ) => s && s.has_baseline === false ) && h(
				'p',
				{ className: 'ts-hint', style: { marginTop: '10px', color: '#b45309' } },
				'⚠️ No baseline recorded yet for some themes / unverifiable plugins / must-use plugins / drop-ins. Click “Snapshot baseline” so tampering — and any newly-planted drop-in backdoor or malicious premium plugin — can be detected on future runs.'
			),
			busy === 'integrity' && h( 'div', { className: 'ts-job-progress', style: { marginTop: '12px' } },
				h( 'div', { className: 'ts-job-bar' },
					h( 'div', { className: 'ts-job-bar__fill ts-job-bar__fill--indeterminate' } )
				),
				h( 'div', { className: 'ts-job-progress__footer' },
					h( 'span', { className: 'ts-spinner ts-spinner--sm', 'aria-hidden': 'true' } ),
					h( 'span', { className: 'ts-job-progress__step' },
						'Fetching checksums from WordPress.org and comparing your files…'
					)
				)
			)
		),

		showScanner && hasRecs && h(
			Card,
			{
				title: 'Recommended fixes',
				actions: h( Badge, { tone: 'warning' }, 'one-click' ),
			},
			h( 'p', { className: 'ts-hint' }, 'These findings are best remediated by reinstalling clean code rather than editing files individually. For a plugin you just installed, use “Verify clean” first — it checks the files against the official WordPress.org copy and clears any that match (false positives) without a reinstall.' ),
			wporgGroups.length > 1 && h( ProGate, {
				feature: 'incident.bulk_repair',
				title: 'Reinstall every flagged plugin at once',
				bullets: [ 'One background job for all flagged WordPress.org plugins', 'Each plugin backed up first, site health-checked between steps' ],
			} ),

			// Live progress for an in-flight single/bulk reinstall (non-blocking).
			repairJob && h( JobProgress, { job: repairSnap, title: repairJob.title } ),

			triage.core && triage.core.count > 0 && h( 'div', { className: 'ts-rec' },
				h( 'div', { className: 'ts-rec__text' },
					h( 'strong', null, '🧬 WordPress core' ),
					h( 'span', { className: 'ts-muted' }, ` ${ triage.core.count } flagged core file(s)` )
				),
				h( Button, { variant: 'primary', disabled: !! busy || !! repairJob, onClick: reinstallCore }, busy === 'core' ? 'Reinstalling…' : 'Reinstall core' )
			),
			wporgGroups.map( ( p ) => h( 'div', { className: 'ts-rec', key: p.slug },
				h( 'div', { className: 'ts-rec__text' },
					h( 'strong', null, '🧩 ' + p.name ),
					h( 'span', { className: 'ts-muted' }, ` ${ p.version || '' } · ${ p.count } flagged file(s)` )
				),
				h( 'div', { className: 'ts-actions-row' },
					h( Button, { variant: 'default', disabled: !! busy || !! repairJob, onClick: () => verifyPlugin( p.slug ), title: 'Check these files against the official WordPress.org copy and clear any that match (false positives)' }, busy === 'vf:' + p.slug ? 'Verifying…' : 'Verify clean' ),
					h( Button, { variant: 'primary', disabled: !! busy || !! repairJob, onClick: () => reinstallPlugin( p.slug ) }, 'Reinstall clean' )
				)
			) )
		),

		showIntegrity && integrity && h(
			Card,
			{ title: 'Integrity summary' },
			h( 'ul', { className: 'ts-modlist' },
				integrity.core && row( 'Core', `${ integrity.core.checked } checked, ${ integrity.core.modified.length } modified, ${ integrity.core.missing.length } missing, ${ ( integrity.core.unknown || [] ).length } unknown`, integrity.core.modified.length || integrity.core.missing.length || ( integrity.core.unknown || [] ).length ),
				integrity.plugins && row(
					'Plugins',
					`${ integrity.plugins.verified } verified, ${ integrity.plugins.modified.length } modified, ${ integrity.plugins.unverifiable.length } unverifiable`,
					integrity.plugins.modified.length || integrity.plugins.unverifiable.length > 0
				),
				( integrity.plugins ? integrity.plugins.unverifiable : [] ).map( ( u ) => row(
					'— ' + u.slug + ' (unverifiable)',
					u.has_baseline
						? `${ u.modified.length } modified, ${ u.added.length } added, ${ u.deleted.length } deleted since baseline`
						: 'not on WordPress.org — no baseline yet, snapshot to enable drift detection',
					u.has_baseline ? ( u.modified.length || u.added.length ) : true
				) ),
				( integrity.mu || [] ).map( ( m ) => row(
					m.source === 'dropins' ? 'Drop-ins' : 'MU-plugins',
					m.has_baseline
						? `${ m.modified.length } modified, ${ m.added.length } added, ${ m.deleted.length } deleted`
						: 'no baseline yet — snapshot to enable drift detection',
					m.has_baseline && ( m.modified.length || m.added.length )
				) )
			)
		),

		h(
			Card,
			{
				title: 'Open findings',
				actions: h( Fragment, null,
					findings.length > 0 && h( Button, { variant: 'default', disabled: refreshing, onClick: refreshFindings, title: 'Re-check every open finding against the current file content and official WordPress.org checksums — clears any that are no longer valid without running a full scan' }, refreshing ? 'Refreshing…' : '🔄 Refresh' ),
					' ',
					findings.length > 0 && h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => bulkClear( 'ignore' ), title: 'Move every open finding to the Ignored list. No files are touched — if an issue is still real, it will reappear as a new open finding on the next scan or Refresh.' }, busy === 'bulk:ignore' ? 'Ignoring…' : 'Ignore all' ),
					' ',
					findings.length > 0 && h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => bulkClear( 'whitelist' ), title: 'Mark all open findings safe and skip them in future scans' }, busy === 'bulk:whitelist' ? 'Whitelisting…' : 'Whitelist all' ),
					' ',
					staleCount > 0 && h( Button, { variant: 'ghost', onClick: dismissStale, title: 'Dismiss findings for files that no longer exist' }, `Dismiss ${ staleCount } stale` ),
					' ',
					h( Badge, { tone: findings.length ? 'danger' : 'success' }, findings.length )
				),
			},
			findings.length > 1 && h( ProGate, {
				feature: 'scanner.cleanup',
				title: 'Clean Site in one click',
				bullets: [ 'Repairs, quarantines or flags every open finding automatically', 'Runs in the background; every repair is backed up and reversible' ],
			} ),
			findings.length > 0 && h( 'div', { className: 'ts-toolbar', style: { display: 'flex', gap: '8px', margin: '0 0 12px' } },
				h( 'input', {
					id: 'ts-scan-findings-search',
					name: 'findings_search',
					type: 'text',
					placeholder: 'Search path, rule, category, or detail…',
					value: findingsQuery,
					onChange: ( e ) => setFindingsQuery( e.target.value ),
					style: { flex: '1 1 auto', minWidth: '200px' },
				} ),
				h( 'select', { id: 'ts-scan-findings-severity', name: 'findings_severity', value: findingsSeverity, onChange: ( e ) => setFindingsSeverity( e.target.value ) },
					h( 'option', { value: '' }, 'All severities' ),
					h( 'option', { value: 'critical' }, 'Critical' ),
					h( 'option', { value: 'warning' }, 'Warning' ),
					h( 'option', { value: 'notice' }, 'Notice' )
				),
				( findingsQuery || findingsSeverity ) && h( Button, { variant: 'ghost', onClick: () => { setFindingsQuery( '' ); setFindingsSeverity( '' ); } }, 'Clear' )
			),
			findingsError
				? h( LoadError, { message: findingsError, onRetry: loadFindings } )
				: findings.length === 0
				? h( EmptyState, { icon: '✅', title: 'No open findings', hint: 'Nothing suspicious detected.' } )
				: visibleFindings.length === 0
				? h( EmptyState, { icon: '🔍', title: 'No matching findings', hint: 'Try a different search term or clear the filter.' } )
				: h( 'table', { className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Sev' ), h( 'th', null, 'Threat' ), h( 'th', null, 'Path' ),
							h( 'th', null, 'Line' ), h( 'th', null, 'Detail' ), h( 'th', null, 'Actions' )
						) ),
						h( 'tbody', null, pagedFindings.map( ( f ) =>
							h( 'tr', { key: f.id },
								h( 'td', null,
									h( Badge, { tone: severityTone( Number( f.severity ) ) }, sevLabel( f.severity ) )
								),
								h( 'td', null, h( 'span', { className: 'ts-evt__text' }, h( 'span', { className: 'ts-row__name' }, h( 'strong', null, threatMeta( f.category ).label ), h( InfoTip, { help: threatMeta( f.category ), label: threatMeta( f.category ).label } ) ), h( 'code', { className: 'ts-evt__code' }, f.rule ) ) ),
								h( 'td', { className: 'ts-uri', title: f.path }, locationLabel( f.path ) ),
								h( 'td', null, f.line || '—' ),
								h( 'td', { className: 'ts-uri', title: f.snippet }, f.snippet || '—' ),
								h( 'td', null, rowActions( f ) )
							)
						) )
				  ),
				findingsPager
		),

		h(
			Card,
			{ title: 'Recent scans' },
			recent.length === 0
				? h( EmptyState, { icon: '🕑', title: 'No completed scans yet', hint: 'Run a scan to start building history.' } )
				: h( 'table', { className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Completed' ), h( 'th', null, 'Files' ),
							h( 'th', null, 'Critical' ), h( 'th', null, 'Warning' ), h( 'th', null, 'Notice' )
						) ),
						h( 'tbody', null, recent.map( ( s, i ) => {
							const fc = s.findings || {};
							return h( 'tr', { key: s.scan_id || i },
								h( 'td', null, s.completed_at || '—' ),
								h( 'td', null, s.files_scanned || 0 ),
								h( 'td', null, h( Badge, { tone: fc.critical ? 'danger' : 'success' }, fc.critical || 0 ) ),
								h( 'td', null, h( Badge, { tone: fc.warning ? 'warning' : 'success' }, fc.warning || 0 ) ),
								h( 'td', null, h( Badge, { tone: fc.notice ? 'neutral' : 'success' }, fc.notice || 0 ) )
							);
						} ) )
				  )
		)
	);

	function rowActions( f ) {
		const id = Number( f.id );
		// File no longer exists on disk — only allow ignoring.
		if ( f.file_missing ) {
			return h( Fragment, null,
				h( Badge, { tone: 'neutral' }, 'File missing' ),
				' ',
				h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => act( f, 'ignored' ) }, 'Ignore' )
			);
		}
		// Covered by a one-click group repair above.
		if ( coreIds.has( id ) ) {
			return h( 'span', { className: 'ts-muted', title: 'Use "Reinstall core" above' }, '↑ via core reinstall' );
		}
		const pg = pluginById.get( id );
		if ( pg && pg.on_wporg ) {
			return h( 'span', { className: 'ts-muted', title: 'Use the plugin reinstall above' }, '↑ via plugin reinstall' );
		}
		const inspectBtn = isFile( f.path ) && h( Button, { variant: 'default', disabled: !! busy, onClick: () => setInspecting( f ) }, 'Inspect' );
		// Whole-file threats (an unexpected/planted file) can't be surgically cleaned — the
		// entire file is the intruder. Offer inspect / delete / quarantine, not "Fix".
		if ( isWholeFileThreat( f ) ) {
			return h( Fragment, null,
				inspectBtn, ' ',
				isFile( f.path ) && h( Button, { variant: 'danger', disabled: !! busy, onClick: () => removeFile( f ) }, busy === 'rm:' + f.id ? 'Deleting…' : 'Delete' ),
				' ',
				isFile( f.path ) && h( Button, { variant: 'default', disabled: !! busy, onClick: () => act( f, 'quarantined' ) }, 'Quarantine' ),
				' ',
				h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => act( f, 'ignored' ) }, 'Ignore' ),
				' ',
				isFile( f.path ) && h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => whitelistOne( f ), title: 'Mark safe and skip in future scans' }, busy === 'wl:' + f.id ? 'Whitelisting…' : 'Whitelist' )
			);
		}
		// Per-file remediation for premium/custom/theme code.
		return h( Fragment, null,
			inspectBtn, ' ',
			isFile( f.path ) && h( Button, { variant: 'primary', disabled: !! busy, onClick: () => fixFile( f ) }, busy === 'fx:' + f.id ? 'Fixing…' : 'Fix' ),
			' ',
			isFile( f.path ) && h( Button, { variant: 'danger', disabled: !! busy, onClick: () => removeFile( f ) }, busy === 'rm:' + f.id ? 'Deleting…' : 'Delete' ),
			' ',
			isFile( f.path ) && h( Button, { variant: 'default', disabled: !! busy, onClick: () => act( f, 'quarantined' ) }, 'Quarantine' ),
			' ',
			h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => act( f, 'ignored' ) }, 'Ignore' ),
			' ',
			isFile( f.path ) && h( Button, { variant: 'ghost', disabled: !! busy, onClick: () => whitelistOne( f ), title: 'Mark safe and skip in future scans' }, busy === 'wl:' + f.id ? 'Whitelisting…' : 'Whitelist' )
		);
	}

	function row( label, value, bad ) {
		return h( 'li', { className: 'ts-modlist__item' }, h( 'span', null, label ), h( Badge, { tone: bad ? 'warning' : 'success' }, value ) );
	}
}

function sevLabel( s ) {
	s = Number( s );
	return s >= 40 ? 'critical' : s >= 30 ? 'warning' : s >= 20 ? 'notice' : 'info';
}

function isFile( path ) {
	return ! /^(post:|postmeta:|term:|termmeta:|option:|user:|theme:|comment:|usermeta:|snippet:|mu:|dropin:|plugin:|core:|db:)/.test( path );
}

// Database findings store a locator (e.g. "user:4", "option:foo") instead of a file path
// because the threat lives in the database, not on disk. Render those as a clear, human-readable
// location so the column never looks empty/cryptic; file paths pass through unchanged.
function locationLabel( path ) {
	path = String( path || '' );
	let m;
	if ( ( m = path.match( /^user:(.+)$/ ) ) )   return '👤 Database · User #' + m[ 1 ];
	if ( ( m = path.match( /^option:(.+)$/ ) ) ) return '⚙️ Database · Option “' + m[ 1 ] + '”';
	if ( ( m = path.match( /^post:(.+)$/ ) ) )   return '📝 Database · Post #' + m[ 1 ];
	if ( ( m = path.match( /^postmeta:(\d+):(.+)$/ ) ) ) return '📝 Database · Post #' + m[ 1 ] + ' field “' + m[ 2 ] + '”';
	if ( ( m = path.match( /^term:(.+)$/ ) ) )     return '🏷️ Database · Term #' + m[ 1 ] + ' description';
	if ( ( m = path.match( /^termmeta:(\d+):(.+)$/ ) ) ) return '🏷️ Database · Term #' + m[ 1 ] + ' field “' + m[ 2 ] + '”';
	if ( ( m = path.match( /^snippet:(.+)$/ ) ) )  return '🧩 Database · Code snippet #' + m[ 1 ];
	if ( ( m = path.match( /^theme:(.+)$/ ) ) )  return '🎨 Theme · ' + m[ 1 ];
	if ( ( m = path.match( /^comment:(.+)$/ ) ) )  return '💬 Database · Comment #' + m[ 1 ];
	if ( ( m = path.match( /^usermeta:(.+)$/ ) ) ) return '🗄️ Database · Usermeta ' + m[ 1 ];
	if ( ( m = path.match( /^mu:(.+)$/ ) ) )       return '⚡ MU-Plugin · ' + m[ 1 ];
	if ( ( m = path.match( /^dropin:(.+)$/ ) ) )   return '🔌 Drop-in · ' + m[ 1 ];
	if ( ( m = path.match( /^plugin:(.+)$/ ) ) )   return '🧩 Plugin · ' + m[ 1 ];
	if ( path === 'core:wordpress' )              return '🌐 WordPress core';
	return path; // already a (masked) file path
}

// Findings where the whole file is the threat (a planted/unexpected file) rather than an
// injected snippet in an otherwise-legitimate file — quarantine, don't "fix".
function isWholeFileThreat( f ) {
	return f.rule === 'integrity-core-unknown';
}
