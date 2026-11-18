"""Transport failures are never model answers; usage and execution are separate."""
import json
from .harness import PolicyError


class RequestQuarantined(PolicyError):
    stop_reason = 'REQUEST_QUARANTINED'

    def __init__(self, message, *, request_key=None, outcome='UNKNOWN_QUARANTINED', origin=None):
        super().__init__(message)
        self.request_key = request_key
        self.outcome = outcome
        self.origin = origin


def transport_failure(error):
    """Parse only transport-generated diagnostics, never repair model JSON."""
    prefix = 'OpenLux request failed '
    if not isinstance(error, PolicyError) or not str(error).startswith(prefix):
        return None
    try:
        value = json.loads(str(error)[len(prefix):])
    except (ValueError, TypeError):
        return None
    status = value.get('http_status')
    return {
        'outcome': 'FAILED_HTTP' if type(status) is int and 400 <= status <= 599 else 'UNKNOWN_QUARANTINED',
        'http_status': status, 'provider_request_id': value.get('request_id'),
        'cause_type': value.get('cause_type'), 'error_type': value.get('error_type'),
        'elapsed_seconds': value.get('elapsed_seconds'),
        'usage_status': 'UNKNOWN', 'currency_cost': 'UNKNOWN',
        'automatic_retry_allowed': False,
    }


def accounting(path):
    """Legacy keys retain their meaning; isolated unknown usage remains visible."""
    starts = {}; responses = {}; outcomes = {}; historical = {}
    for raw in path.read_bytes().splitlines() if path.exists() else []:
        row = json.loads(raw); key = row.get('request_key'); kind = row.get('event')
        if kind == 'request_started':
            if key in starts:
                raise ValueError('Duplicate physical start identity; no guessed settlement')
            starts[key] = row
        elif kind == 'response':
            if key in responses:
                raise ValueError('Duplicate response identity; no double accounting')
            responses[key] = row
        elif kind == 'request_outcome':
            if row.get('outcome') not in {'FAILED_HTTP', 'UNKNOWN_QUARANTINED'}:
                raise ValueError('Invalid transport outcome')
            if key in outcomes and outcomes[key] != row:
                raise ValueError('Conflicting failure outcomes')
            outcomes[key] = row
        elif kind == 'historical_request_quarantined':
            historical[key] = row
    if any(key not in starts for key in outcomes):
        raise ValueError('Failure outcome without physical start')
    reported = 0; unsettled = []; active = []; failures = []; isolated = []
    for key, start in starts.items():
        response = responses.get(key)
        total = response.get('usage', {}).get('total_tokens') if response else None
        if type(total) is int and total >= 0:
            reported += total
        else:
            unsettled.append(start['reserved_tokens'])
            if key not in outcomes:
                active.append(key)
        if not response and key in outcomes:
            isolated.append(key)
            if outcomes[key]['outcome'] == 'FAILED_HTTP':
                failures.append(key)
    return {
        'physical_requests': len(starts), 'reported_tokens': reported,
        'unsettled_reserved_tokens': sum(unsettled), 'unsettled_requests': len(unsettled),
        'active_unsettled_requests': len(active), 'quarantined_requests': len(isolated),
        'failed_http_requests': len(failures),
        'unknown_execution_quarantined_requests': len(isolated) - len(failures),
        'historical_quarantined_requests': len(historical),
        'failed_request_usage_unknown': len(isolated),
        'failure_is_not_success': True,
    }
