"""SentinelForge from a terminal, for a build pipeline.

    python -m app.cli scan PATH [--fail-on high] [--sarif out.sarif] …

Everything the web application does to a repository needs a database, an
account and somebody to click. A pipeline has none of those. This package runs
the same analyser over a folder, builds the same report, and turns the result
into an exit code — which is the only thing a build system reads.

It needs no database and no configuration, opens no network connection, and —
like every other part of this project — never executes anything it scans.
"""
