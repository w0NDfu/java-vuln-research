"""Intersect only an explicitly identified callable's requested source window."""


def clip_exact_window(request, symbols, aliases):
    if (request.get('action') != 'inspect_entity'
            or set(request) != {'action', 'entity_id', 'start_line', 'end_line'}):
        return None
    identity = request.get('entity_id')
    if not isinstance(identity, str):
        return None
    method = symbols.methods.get(aliases.get(identity, identity))
    first, last = request['start_line'], request['end_line']
    if method is None or type(first) is not int or type(last) is not int or first > last:
        return None
    lo, hi = max(first, method.start_line), min(last, method.end_line)
    if lo > hi or hi - lo + 1 > 160 or (lo, hi) == (first, last):
        return None
    return {'original_request': dict(request), 'action': {**request, 'start_line': lo, 'end_line': hi},
            'status': 'CLIPPED_EXACT_METHOD', 'changed': True,
            'selected_method': symbols.describe(method), 'returned_range': [lo, hi],
            'excluded_requested_ranges': [[a, b] for a, b in ((first, lo - 1), (hi + 1, last)) if a <= b],
            'reason': 'Only the intersection with the explicitly identified method is returned; excluded context is unknown.'}
