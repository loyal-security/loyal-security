/**
 * Reusable async-job progress display.
 *
 * useJobPoller — polls GET /jobs/{id} every 2 s and calls onDone / onError when the job
 *               settles. Returns the latest job snapshot (null while the first fetch is pending).
 *
 * JobProgress  — renders an animated bar + current step + recent-steps activity feed.
 *               Designed to be embedded inline in a Card body, not shown as a modal.
 */
import { h, useState, useEffect, useRef } from '../el.js';
import { api } from '../api.js';

/**
 * @param {string|null} jobId
 * @param {{ onDone?: function, onError?: function, interval?: number }} [opts]
 * @returns {object|null} Latest job snapshot.
 */
export function useJobPoller( jobId, { onDone, onError, interval = 2000 } = {} ) {
	const [ job, setJob ] = useState( null );
	const timer           = useRef( null );
	const alive           = useRef( true );

	useEffect( () => {
		if ( ! jobId ) {
			setJob( null );
			return;
		}
		alive.current = true;

		const poll = async () => {
			try {
				const j = await api.get( '/jobs/' + jobId );
				if ( ! alive.current ) return;
				setJob( j );
				if ( j.status === 'done' ) {
					clearInterval( timer.current );
					if ( onDone ) onDone( j );
				} else if ( j.status === 'error' ) {
					clearInterval( timer.current );
					if ( onError ) onError( j );
				}
			} catch ( _ ) { /* ignore transient poll failures */ }
		};

		poll(); // immediate first hit
		timer.current = setInterval( poll, interval );

		return () => {
			alive.current = false;
			clearInterval( timer.current );
		};
	}, [ jobId ] );

	return job;
}

/**
 * @param {{ job: object|null, title?: string }} props
 */
export function JobProgress( { job, title } ) {
	const pct   = job ? ( job.pct || 0 ) : 0;
	const done  = job && job.status === 'done';
	const err   = job && job.status === 'error';
	// Warn if still queued after 15 s — cron may not be firing automatically.
	const stale = job && job.status === 'queued' && ( Math.floor( Date.now() / 1000 ) - ( job.created || 0 ) ) > 15;
	// Recent steps: skip the current one, show up to 4 past ones newest-first.
	const past  = job && job.steps ? [ ...job.steps ].reverse().slice( 1, 5 ) : [];

	return h(
		'div',
		{ className: 'ts-job-progress' },

		title && h( 'div', { className: 'ts-job-progress__title' }, title ),

		// Progress bar.
		h( 'div', { className: 'ts-job-bar' },
			h( 'div', {
				className: [
					'ts-job-bar__fill',
					done ? 'ts-job-bar__fill--done' : '',
					err  ? 'ts-job-bar__fill--err'  : '',
				].join( ' ' ).trim(),
				style: { width: ( done ? 100 : pct ) + '%' },
			} )
		),

		// Status line.
		h( 'div', { className: 'ts-job-progress__footer' },
			! done && ! err && h( 'span', { className: 'ts-spinner ts-spinner--sm', 'aria-hidden': 'true' } ),
			done  && h( 'span', { className: 'ts-job-icon ts-job-icon--done' }, '✓' ),
			err   && h( 'span', { className: 'ts-job-icon ts-job-icon--err'  }, '✗' ),
			h( 'span', {
				className: 'ts-job-progress__step' + ( err ? ' ts-job-progress__step--err' : '' ),
			}, job ? job.step : 'Starting…' ),
			h( 'span', { className: 'ts-job-progress__pct' }, pct + '%' )
		),

		// Stale-queue warning (cron not firing).
		stale && h(
			'p',
			{ className: 'ts-job-progress__warn' },
			'⚠️ The job is taking longer than expected to start. ' +
			'If your host uses an alternative cron scheduler, the backup will still complete on the next page load.'
		),

		// Activity feed: past steps.
		past.length > 0 && h(
			'ul',
			{ className: 'ts-job-steps' },
			past.map( ( s, i ) =>
				h( 'li', { key: i, className: 'ts-job-steps__past' }, s.msg )
			)
		)
	);
}
