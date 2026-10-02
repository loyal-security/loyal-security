/**
 * Shared accessor for the per-admin Basic/Advanced dashboard density preference (see store.js).
 * Small enough that most callers could just read useStore().state.viewMode directly — this
 * exists so the "advanced" comparison and the no-store fallback aren't repeated at every
 * call site, and so panels read as intent ("is this the advanced view?") rather than a
 * string comparison.
 */
import { useStore } from '../store.js';

export function useIsAdvancedView() {
	const store = useStore();
	return ! store || store.state.viewMode === 'advanced';
}
