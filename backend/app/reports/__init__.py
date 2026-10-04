"""Reports: one repository's findings in a form that can be handed to someone.

``model`` builds a plain, frozen description of the repository's state from
rows the earlier phases wrote. The renderers turn that one description into
Markdown, a self-contained HTML page, or SARIF. Nothing in this package talks
to the database, the network or a model.
"""
