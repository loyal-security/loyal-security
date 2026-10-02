/**
 * Reusable presentational components shared across panels.
 */
import { h, cx, useState, useEffect, useRef } from '../el.js';
import { useStore } from '../store.js';

export function Spinner( { label } ) {
	return h( 'span', { className: 'ts-spinner', role: 'status', 'aria-label': label || 'Loading' } );
}

/** Labeled form-field wrapper (label + control + optional hint) shared by any settings-style
 * form — originally local to AgencyPanel.js, promoted here once a second file needed it too. */
export function FieldRow( { label, hint, children, id } ) {
	return h(
		'div',
		{ className: 'ts-agency-field' },
		h( 'label', { className: 'ts-agency-field__label', htmlFor: id }, label ),
		children,
		hint && h( 'p', { className: 'ts-agency-field__hint' }, hint )
	);
}

export function Card( { title, actions, children, className } ) {
	return h(
		'section',
		{ className: cx( 'ts-card', className ) },
		( title || actions ) &&
			h(
				'header',
				{ className: 'ts-card__head' },
				title && h( 'h2', { className: 'ts-card__title' }, title ),
				actions && h( 'div', { className: 'ts-card__actions' }, actions )
			),
		h( 'div', { className: 'ts-card__body' }, children )
	);
}

/**
 * A fixed-height, independently-scrolling container for content that would otherwise make the
 * whole page scroll as one long unit (long lists, tables, activity feeds). Children scroll inside
 * this box on their own scrollbar; the rest of the page — and the page's own scroll position —
 * stays put. Pass `maxHeight` to override the default for content that needs more or less room.
 */
export function ScrollPanel( { children, maxHeight = '360px', className } ) {
	return h(
		'div',
		{ className: cx( 'ts-scroll-panel', className ), style: { maxHeight } },
		children
	);
}

export function Button( { children, onClick, variant = 'default', disabled, type = 'button', title } ) {
	return h(
		'button',
		{
			type,
			title,
			disabled: !! disabled,
			onClick,
			className: cx( 'ts-btn', 'ts-btn--' + variant, { 'is-disabled': !! disabled } ),
		},
		children
	);
}

export function Badge( { children, tone = 'neutral' } ) {
	return h( 'span', { className: cx( 'ts-badge', 'ts-badge--' + tone ) }, children );
}

let toggleAutoId = 0;

export function Toggle( { checked, onChange, label, disabled, id, name } ) {
	const [ autoId ] = useState( () => 'ts-toggle-' + ( ++toggleAutoId ) );
	const fieldId = id || autoId;
	return h(
		'label',
		{ className: cx( 'ts-toggle', { 'ts-toggle--disabled': !! disabled } ), htmlFor: fieldId },
		h( 'input', {
			id: fieldId,
			name: name || fieldId,
			type: 'checkbox',
			checked: !! checked,
			disabled: !! disabled,
			onChange: disabled ? undefined : ( e ) => onChange( e.target.checked ),
		} ),
		h( 'span', { className: 'ts-toggle__track' }, h( 'span', { className: 'ts-toggle__thumb' } ) ),
		label && h( 'span', { className: 'ts-toggle__label' }, label )
	);
}

export function EmptyState( { icon = '🛡️', title, hint } ) {
	return h(
		'div',
		{ className: 'ts-empty' },
		h( 'div', { className: 'ts-empty__icon' }, icon ),
		h( 'h3', null, title ),
		hint && h( 'p', null, hint )
	);
}

/**
 * Retryable error state for a panel's initial data load. Distinct from EmptyState: a failed
 * request must never be presented the same as "genuinely nothing here" (a false all-clear on a
 * security dashboard is worse than an ugly error), and must never leave the panel stuck on a
 * bare spinner forever with no way to recover but a full page reload.
 */
export function LoadError( { message, onRetry } ) {
	return h(
		'div',
		{ className: 'ts-notice ts-notice--danger', style: { display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'space-between' } },
		h( 'span', null, '⚠️ ' + ( message || 'Something went wrong loading this data.' ) ),
		onRetry && h( Button, { variant: 'ghost', onClick: onRetry }, 'Retry' )
	);
}

export function severityTone( severity ) {
	if ( severity >= 40 ) return 'danger';
	if ( severity >= 30 ) return 'warning';
	if ( severity >= 20 ) return 'info';
	return 'neutral';
}

/**
 * An (i) help button that reveals a popover explaining a setting: what it does, what
 * happens when enabled, and the security risk if disabled/misconfigured. Pass a `help`
 * object shaped { what, on, off } (see settings-help.js); any field may be omitted.
 * Click to toggle; click the ✕ or the backdrop to close.
 */
export function InfoTip( { help, label } ) {
	const [ open, setOpen ] = useState( false );
	// Popovers default to opening rightward/downward from the icon (see .ts-infotip__pop's
	// `left: 0; top: calc(100% + 8px)`), which overflows the viewport — and, worse, forces an
	// unwanted horizontal scrollbar on an ancestor Modal — whenever the icon sits near the right
	// edge of a card or a narrow popup (e.g. the last item in a 2-column settings grid). Measured
	// after paint and flipped to anchor from the opposite edge instead of guessing from layout.
	const [ flip, setFlip ] = useState( { x: false, y: false } );
	const popRef = useRef( null );

	useEffect( () => {
		if ( ! open || ! popRef.current ) return;
		const rect = popRef.current.getBoundingClientRect();
		setFlip( {
			x: rect.right > window.innerWidth - 8,
			y: rect.bottom > window.innerHeight - 8,
		} );
	}, [ open ] );

	if ( ! help ) return null;

	return h(
		'span',
		{ className: 'ts-infotip' },
		h(
			'button',
			{
				type: 'button',
				className: 'ts-infotip__btn',
				'aria-label': label ? 'Explain: ' + label : 'What does this do?',
				'aria-expanded': open ? 'true' : 'false',
				onClick: ( e ) => { e.preventDefault(); e.stopPropagation(); setOpen( ! open ); },
			},
			'i'
		),
		open && h(
			'span',
			null,
			h( 'span', { className: 'ts-infotip__backdrop', onClick: () => setOpen( false ) } ),
			h(
				'span',
				{
					className: cx( 'ts-infotip__pop', flip.x && 'ts-infotip__pop--right', flip.y && 'ts-infotip__pop--up' ),
					role: 'dialog',
					ref: popRef,
				},
				label && h( 'span', { className: 'ts-infotip__title' }, label ),
				help.what && h( 'span', { className: 'ts-infotip__what' }, help.what ),
				help.on && h(
					'span',
					{ className: 'ts-infotip__row ts-infotip__row--on' },
					h( 'span', { className: 'ts-infotip__tag' }, 'When enabled' ),
					h( 'span', null, help.on )
				),
				help.off && h(
					'span',
					{ className: 'ts-infotip__row ts-infotip__row--off' },
					h( 'span', { className: 'ts-infotip__tag' }, 'Risk if off' ),
					h( 'span', null, help.off )
				),
				h( 'button', { type: 'button', className: 'ts-infotip__close', 'aria-label': 'Close', onClick: () => setOpen( false ) }, '✕' )
			)
		)
	);
}

/**
 * Shared confirm-before-acting modal for any action that isn't safely reversible with a
 * click. Replaces native window.confirm() — a native dialog is the one place in this app
 * that breaks the app's own visual language and blocks the page until dismissed. `message`
 * states what will actually happen; `consequence` is an optional second line for the
 * irreversibility/blast-radius detail (kept separate so the headline stays readable).
 * `danger` picks the confirm button's variant; `busy` disables both buttons and swaps the
 * confirm label for a spinner while the wrapped action is in flight.
 */
export function ConfirmDialog( { open, title, message, consequence, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = true, busy, onConfirm, onCancel } ) {
	useEffect( () => {
		if ( ! open ) return undefined;
		const onKey = ( e ) => {
			if ( e.key === 'Escape' && ! busy ) onCancel();
		};
		document.addEventListener( 'keydown', onKey );
		return () => document.removeEventListener( 'keydown', onKey );
	}, [ open, busy, onCancel ] );

	if ( ! open ) return null;

	return h(
		'div',
		{ className: 'ts-confirm' },
		h( 'div', { className: 'ts-confirm__backdrop', onClick: () => ! busy && onCancel() } ),
		h(
			'div',
			{ className: 'ts-confirm__panel', role: 'alertdialog', 'aria-modal': 'true', 'aria-label': title },
			h( 'h3', { className: 'ts-confirm__title' }, title ),
			message && h( 'p', { className: 'ts-confirm__message' }, message ),
			consequence && h( 'p', { className: 'ts-confirm__consequence' }, consequence ),
			h(
				'div',
				{ className: 'ts-confirm__actions' },
				h( Button, { variant: 'ghost', disabled: !! busy, onClick: onCancel }, cancelLabel ),
				h(
					Button,
					{ variant: danger ? 'danger' : 'primary', disabled: !! busy, onClick: onConfirm },
					busy ? h( Spinner, null ) : confirmLabel
				)
			)
		)
	);
}

/**
 * Generic "detail popup" for moving a cluster of related cards (a settings group, a rules list,
 * a review queue — anything that would otherwise make a panel page too long) out of the page flow
 * and into an on-demand overlay, opened from a compact summary card. Content scrolls inside the
 * panel body on its own; the page behind it does not move. First used to collapse the Firewall
 * panel's five Bot Management cards behind one summary card — reuse this for the same pattern
 * elsewhere rather than building another bespoke overlay per feature.
 *
 * @param {Object}   props
 * @param {boolean}  props.open    Whether the modal is visible.
 * @param {Function} props.onClose Called on backdrop click, Escape, or the × button.
 * @param {string}   props.title   Header text.
 * @param {string}   [props.icon]  Optional leading emoji for the header.
 * @param {'md'|'lg'} [props.size] 'md' (560px, the default) or 'lg' (900px) — pick 'lg' once the
 *                                 content includes tables or multiple stacked cards.
 * @param {*}        props.children Body content — typically one or more <Card> elements.
 */
export function Modal( { open, onClose, title, icon, size = 'md', children } ) {
	useEffect( () => {
		if ( ! open ) return undefined;
		const onKey = ( e ) => {
			if ( e.key === 'Escape' ) onClose();
		};
		document.addEventListener( 'keydown', onKey );
		// Lock the page behind the modal so there is only ever one scroll position in play.
		const prevOverflow = document.body.style.overflow;
		document.body.style.overflow = 'hidden';
		return () => {
			document.removeEventListener( 'keydown', onKey );
			document.body.style.overflow = prevOverflow;
		};
	}, [ open, onClose ] );

	if ( ! open ) return null;

	return h(
		'div',
		{ className: 'ts-modal' },
		h( 'div', { className: 'ts-modal__backdrop', onClick: onClose } ),
		h(
			'div',
			{
				className: cx( 'ts-modal__panel', 'lg' === size && 'ts-modal__panel--lg' ),
				role: 'dialog',
				'aria-modal': 'true',
				'aria-label': title,
			},
			h(
				'header',
				{ className: 'ts-modal__header' },
				h( 'h3', { className: 'ts-modal__title' }, icon && h( 'span', { 'aria-hidden': 'true' }, icon + ' ' ), title ),
				h( 'button', { type: 'button', className: 'ts-modal__close', 'aria-label': 'Close', onClick: onClose }, '×' )
			),
			h( 'div', { className: 'ts-modal__body' }, children )
		)
	);
}

/** Toast viewport — rendered once near the app root. */
export function Toasts() {
	const store = useStore();
	if ( ! store ) return null;
	return h(
		'div',
		{ className: 'ts-toasts' },
		store.state.toasts.map( ( t ) =>
			h(
				'div',
				{ key: t.id, className: cx( 'ts-toast', 'ts-toast--' + t.kind ), onClick: () => store.dismissToast( t.id ) },
				t.message
			)
		)
	);
}
