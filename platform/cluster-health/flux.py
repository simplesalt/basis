"""Stuck Flux reconciliation check -- not implemented yet.

Same interface as finalizers.check and crossplane.check so server.py can
sum all three unconditionally: `check(client, now) -> list` of problem
dicts shaped like finalizers.CATEGORY's ({category, severity, kind,
apiVersion, namespace, name, detail, ...}). Returns [] until a later task
fills it in.
"""


def check(client, now):
    return []
