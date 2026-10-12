"""Allowlisted account quota fields from the official Codex App Server."""
import math


def number(value, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    if value < minimum or (maximum is not None and value > maximum):
        return None
    return value


def label(value):
    return value[:160] if isinstance(value, str) else None


def window(value):
    if not isinstance(value, dict):
        return None
    used = number(value.get('usedPercent'), maximum=100)
    return {'used_percent': used, 'remaining_percent': 100 - used if used is not None else None,
        'duration_minutes': number(value.get('windowDurationMins'), minimum=1),
        'resets_at': number(value.get('resetsAt'), maximum=253402300799)}


def normalize_usage(result):
    if not isinstance(result, dict):
        result = {}
    snapshots = result.get('rateLimitsByLimitId')
    if not isinstance(snapshots, dict) or not snapshots:
        snapshots = {'codex': result.get('rateLimits')}
    buckets = []
    for key, snapshot in snapshots.items():
        if not isinstance(snapshot, dict):
            continue
        credits = snapshot.get('credits')
        credits = {'balance': label(credits.get('balance')),
            'has_credits': credits.get('hasCredits') if isinstance(credits.get('hasCredits'), bool) else None,
            'unlimited': credits.get('unlimited') if isinstance(credits.get('unlimited'), bool) else None} if isinstance(credits, dict) else None
        buckets.append({'id': label(snapshot.get('limitId')) or label(key),
            'name': label(snapshot.get('limitName')), 'primary': window(snapshot.get('primary')),
            'secondary': window(snapshot.get('secondary')), 'credits': credits,
            'limit_reached': label(snapshot.get('rateLimitReachedType')),
            'spend_control_reached': snapshot.get('spendControlReached') is True})
    allowed = result.get('ordinaryUsageAllowed')
    return {'buckets': buckets, 'ordinary_usage_allowed': allowed if isinstance(allowed, bool) else None}
