/**
 * Health Score widget — compact A–F grade card with an expandable checklist.
 *
 * Fetches `/status/health-score` (free). Embeddable in the dashboard overview.
 */
import { h, useState, useEffect } from '../el.js';
import { api } from '../api.js';
import { Card, Spinner } from './ui.js';

function gradeTone( grade ) {
	if ( grade === 'A' || grade === 'B' ) return 'is-good';
	if ( grade === 'C' ) return 'is-mid';
	return 'is-bad';
}

export function HealthScoreWidget() {
	const [ data, setData ] = useState( null );
	const [ open, setOpen ] = useState( false );

	useEffect( () => {
		let alive = true;
		api.get( '/status/health-score' ).then( ( d ) => alive && setData( d ) ).catch( () => {} );
		return () => {
			alive = false;
		};
	}, [] );

	if ( ! data ) {
		return h( Card, { title: 'Security Health' }, h( Spinner, { label: 'Scoring…' } ) );
	}

	const checks = data.checks || [];

	return h(
		Card,
		{
			title: 'Security Health',
			className: 'ts-health',
			actions: h(
				'button',
				{
					type: 'button',
					className: 'ts-health__toggle',
					onClick: () => setOpen( ! open ),
				},
				open ? 'Hide details' : 'Show details'
			),
		},
		h(
			'div',
			{ className: 'ts-health__summary' },
			h( 'div', { className: 'ts-health__grade ' + gradeTone( data.grade ) }, data.grade ),
			h(
				'div',
				{ className: 'ts-health__score' },
				h( 'strong', null, data.score ),
				h( 'span', null, '/100' )
			)
		),
		open &&
			h(
				'ul',
				{ className: 'ts-health__checks' },
				checks.map( ( c ) =>
					h(
						'li',
						{ key: c.id, className: c.pass ? 'is-pass' : 'is-fail' },
						h( 'span', { className: 'ts-health__icon' }, c.pass ? '✓' : '✕' ),
						h( 'span', { className: 'ts-health__label' }, c.label ),
						! c.pass && h( 'span', { className: 'ts-health__impact' }, '-' + c.impact )
					)
				)
			)
	);
}
