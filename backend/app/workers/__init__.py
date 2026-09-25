"""Background workers.

Work that must not happen inside an HTTP request lives here. Phase 6 has one:
the scan worker, which claims queued scans from the database and runs them.
"""
