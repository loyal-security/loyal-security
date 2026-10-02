/**
 * A single human-readable security event in the dashboard activity feed.
 *
 * Renders the plain-language title, a one-line explanation of what happened, the source
 * IP and a relative timestamp, and a worded severity badge. Clicking the row expands a
 * full incident report: structured details plus the exact signature matches behind a
 * WAF block (the forensic evidence that proves an attack was stopped).
 */
import { h, useState } from '../el.js';
import { Badge, severityTone } from './ui.js';
import { describeEvent, incidentDetails, attackMatches, relativeTime } from '../events.js';

export function ActivityItem( { event: ev } ) {
	const [ open, setOpen ] = useState( false );
	const d = describeEvent( ev );

	return h(
		'li',
		{ className: 'ts-feed__item' + ( open ? ' is-open' : '' ) },
		h(
			'button',
			{
				type: 'button',
				className: 'ts-feed__row',
				'aria-expanded': open ? 'true' : 'false',
				onClick: () => setOpen( ! open ),
			},
			h( 'span', { className: 'ts-feed__icon', 'aria-hidden': 'true' }, d.icon ),
			h(
				'span',
				{ className: 'ts-feed__main' },
				h(
					'span',
					{ className: 'ts-feed__head' },
					h( 'span', { className: 'ts-feed__title' }, d.title ),
					h( Badge, { tone: severityTone( Number( ev.severity ) ) }, d.sevLabel )
				),
				d.summary && h( 'span', { className: 'ts-feed__summary' }, d.summary ),
				h(
					'span',
					{ className: 'ts-feed__meta' },
					ev.ip ? h( 'span', null, 'IP ', h( 'code', null, ev.ip ) ) : null,
					h( 'span', { title: ev.created_at }, relativeTime( ev.created_at ) )
				)
			),
			h( 'span', { className: 'ts-feed__chevron', 'aria-hidden': 'true' }, open ? '▾' : '▸' )
		),
		open && h( IncidentReport, { event: ev } )
	);
}

/** The expanded incident report: structured details + signature evidence. */
function IncidentReport( { event: ev } ) {
	const details = incidentDetails( ev );
	const matches = attackMatches( ev );

	return h(
		'div',
		{ className: 'ts-incident' },
		details.length
			? h(
					'dl',
					{ className: 'ts-incident__grid' },
					details.map( ( row, i ) =>
						h(
							'div',
							{ key: i, className: 'ts-incident__pair' },
							h( 'dt', null, row.label ),
							h( 'dd', null, row.value )
						)
					)
			  )
			: null,
		matches.length
			? h(
					'div',
					{ className: 'ts-incident__matches' },
					h( 'h4', null, 'Why it was flagged' ),
					h(
						'table',
						{ className: 'ts-table' },
						h( 'thead', null, h( 'tr', null,
							h( 'th', null, 'Rule' ),
							h( 'th', null, 'Type' ),
							h( 'th', null, 'Found in' ),
							h( 'th', null, 'Score' ),
							h( 'th', null, 'Detail' )
						) ),
						h(
							'tbody',
							null,
							matches.map( ( m, i ) =>
								h( 'tr', { key: i },
									h( 'td', null, h( 'code', null, m.rule ) ),
									h( 'td', null, m.category ),
									h( 'td', null, m.where ),
									h( 'td', null, String( m.score ) ),
									h( 'td', null, m.desc )
								)
							)
						)
					)
			  )
			: null
	);
}
