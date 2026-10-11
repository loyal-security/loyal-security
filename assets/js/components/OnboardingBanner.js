/**
 * Onboarding banner — dismissible getting-started guide shown until complete or dismissed.
 *
 * Fetches `/status/onboarding` (free); dismiss posts to `/status/onboarding/dismiss`. The
 * checklist is re-read whenever the screen changes, the browser tab regains focus, or another
 * screen reports a finished setup step (the `loyalsec:setup-changed` window event, sent for
 * example when a scan completes), so the next step appears as soon as the current one is done.
 * When the last step is completed while the banner is showing, it turns into a short "setup
 * complete" confirmation instead of disappearing without a word.
 */
import { h, useState, useEffect, useRef } from '../el.js';
import { api } from '../api.js';

/** Window event other screens send after completing a setup step. */
export const SETUP_CHANGED_EVENT = 'loyalsec:setup-changed';

export function OnboardingBanner() {
	const [ data, setData ] = useState( null );
	const [ hidden, setHidden ] = useState( false );
	const [ justCompleted, setJustCompleted ] = useState( false );
	// Whether this banner has shown an unfinished checklist since the dashboard loaded.
	const sawIncomplete = useRef( false );

	useEffect( () => {
		let alive = true;
		const load = () => api.get( '/status/onboarding' ).then( ( d ) => {
			if ( ! alive || ! d ) {
				return;
			}
			if ( d.percent < 100 ) {
				sawIncomplete.current = true;
			} else if ( sawIncomplete.current ) {
				setJustCompleted( true );
			}
			setData( d );
		} ).catch( () => {} );

		load();
		window.addEventListener( 'hashchange', load );
		window.addEventListener( 'focus', load );
		window.addEventListener( SETUP_CHANGED_EVENT, load );
		return () => {
			alive = false;
			window.removeEventListener( 'hashchange', load );
			window.removeEventListener( 'focus', load );
			window.removeEventListener( SETUP_CHANGED_EVENT, load );
		};
	}, [] );

	// The full-panel OnboardingWizard sets this flag when the user finishes or dismisses it
	// ("Don't show this again"), so the banner stops nagging across reloads.
	let wizardDone = false;
	try { wizardDone = window.localStorage.getItem( 'loyalsec_onboarding_done' ) === '1'; } catch ( e ) {}

	const dismiss = () => {
		setHidden( true );
		api.post( '/status/onboarding/dismiss', {} ).catch( () => {} );
	};

	if ( ! data || hidden || data.dismissed ) {
		return null;
	}

	if ( data.percent >= 100 ) {
		if ( ! justCompleted ) {
			return null;
		}
		return h(
			'div',
			{ className: 'ts-onboarding ts-onboarding--done', role: 'status' },
			h(
				'div',
				{ className: 'ts-onboarding__head' },
				h( 'h3', { className: 'ts-onboarding__title' }, '✅ Loyal Security is set up' ),
				h(
					'button',
					{ type: 'button', className: 'ts-onboarding__dismiss', onClick: dismiss, 'aria-label': 'Dismiss' },
					'×'
				)
			),
			h( 'p', { className: 'ts-onboarding__hint' }, 'Every setup step is complete. Your site is protected; check the Dashboard for its security score and recent activity.' )
		);
	}

	if ( wizardDone ) {
		return null;
	}

	const steps = data.steps || [];
	const next = steps.find( ( s ) => ! s.optional && ! s.done );

	const go = ( url ) => {
		if ( ! url ) return;
		const target = '/' + url.replace( /^#\/?/, '' );
		if ( window.location.hash === '#' + target ) {
			// Already on this panel — fire a synthetic hashchange so App.js re-renders it.
			window.dispatchEvent( new Event( 'hashchange' ) );
		} else {
			window.location.hash = target;
		}
	};

	return h(
		'div',
		{ className: 'ts-onboarding' },
		h(
			'div',
			{ className: 'ts-onboarding__head' },
			h( 'h3', { className: 'ts-onboarding__title' }, 'Finish setting up Loyal Security' ),
			h(
				'button',
				{ type: 'button', className: 'ts-onboarding__dismiss', onClick: dismiss, 'aria-label': 'Dismiss' },
				'×'
			)
		),
		h(
			'div',
			{ className: 'ts-onboarding__progress' },
			h( 'div', {
				className: 'ts-onboarding__bar',
				style: { width: data.percent + '%' },
			} ),
			h( 'span', { className: 'ts-onboarding__percent' }, data.percent + '% complete' )
		),
		next &&
			h(
				'div',
				{ className: 'ts-onboarding__next' },
				h(
					'div',
					null,
					h( 'strong', null, 'Next: ' + next.label ),
					h( 'p', { className: 'ts-onboarding__hint' }, next.description )
				),
				h(
					'button',
					{ type: 'button', className: 'ts-btn ts-btn--primary', onClick: () => go( next.action_url ) },
					'Go'
				)
			)
	);
}
