"""Repository ingestion: getting untrusted source code onto disk safely.

The rule for every module in this package: **code that arrives here is data,
never something to run.** Nothing is executed, no build step is triggered, no
script inside an archive or repository is invoked, and no file keeps its
execute bit.
"""
