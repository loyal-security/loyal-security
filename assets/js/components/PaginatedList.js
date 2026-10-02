/**
 * Reusable client-side list pagination + search helpers.
 *
 * Long lists (scan findings, CVE vulnerabilities, bans, quarantine, notifications…) render every
 * row at once, which becomes unusable once a list grows to hundreds of entries. These helpers add
 * pagination (and an optional search box) with a 2–3 line change per panel:
 *
 *   const { pageItems, pager } = usePaged( filteredItems, 25 );
 *   …render pageItems.map(...)… then render `pager` beneath the list.
 *
 * Filtering/searching stays in the panel (each list searches different fields); `matchesQuery`
 * is a small helper for the common "does any of these fields contain the query" case.
 */

import { h, useState, useEffect } from '../el.js';

/** Show a search box once a list has at least this many items — one shared threshold so sibling
 * panels (Network Sites, the Hub fleet grid, …) don't each pick their own magic number. */
export const SEARCH_VISIBLE_MIN = 2;

/**
 * Paginate an array. Returns the current page's slice and a ready-to-render pager element
 * (null when everything fits on one page). Resets to page 1 whenever the list shrinks below the
 * current page (e.g. after a filter change) so the view never gets stuck on an empty page.
 *
 * @param {Array}  items    Full (already filtered/sorted) list.
 * @param {number} perPage  Rows per page.
 */
export function usePaged( items, perPage = 25 ) {
	const [ page, setPage ] = useState( 1 );
	const total = items.length;
	const pages = Math.max( 1, Math.ceil( total / perPage ) );

	useEffect( () => {
		if ( page > pages ) {
			setPage( 1 );
		}
	}, [ pages, page ] );

	const start     = ( page - 1 ) * perPage;
	const pageItems = items.slice( start, start + perPage );
	const pager     = total > perPage
		? h( Pager, { page, pages, total, start, count: pageItems.length, setPage } )
		: null;

	return { pageItems, pager, page, setPage };
}

/** Prev / range / Next control. */
export function Pager( { page, pages, total, start, count, setPage } ) {
	return h( 'div', { className: 'ts-pager' },
		h( 'button', {
			type: 'button',
			className: 'ts-pager__btn',
			disabled: page <= 1,
			onClick: () => setPage( page - 1 ),
		}, '‹ Prev' ),
		h( 'span', { className: 'ts-pager__info' }, `${ start + 1 }–${ start + count } of ${ total }` ),
		h( 'button', {
			type: 'button',
			className: 'ts-pager__btn',
			disabled: page >= pages,
			onClick: () => setPage( page + 1 ),
		}, 'Next ›' )
	);
}

let listSearchAutoId = 0;

/** Controlled search input with a consistent look. */
export function ListSearch( { value, onChange, placeholder, id, name } ) {
	const [ autoId ] = useState( () => 'ts-listsearch-' + ( ++listSearchAutoId ) );
	const fieldId = id || autoId;
	return h( 'div', { className: 'ts-listsearch' },
		h( 'span', { className: 'ts-listsearch__icon', 'aria-hidden': 'true' }, '🔍' ),
		h( 'input', {
			id: fieldId,
			name: name || fieldId,
			type: 'search',
			className: 'ts-listsearch__input',
			value,
			placeholder: placeholder || 'Search…',
			'aria-label': placeholder || 'Search',
			onChange: ( e ) => onChange( e.target.value ),
		} )
	);
}

/**
 * True when the lowercased query is empty or is a substring of any of the given field values.
 *
 * @param {Object}   item   Row.
 * @param {string}   query  Search text (already trimmed by the caller if desired).
 * @param {string[]} fields Field names to search.
 */
export function matchesQuery( item, query, fields ) {
	const q = String( query || '' ).toLowerCase();
	if ( '' === q ) {
		return true;
	}
	for ( const f of fields ) {
		const v = item && item[ f ] != null ? String( item[ f ] ).toLowerCase() : '';
		if ( v.indexOf( q ) !== -1 ) {
			return true;
		}
	}
	return false;
}
