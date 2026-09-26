"""Readers that turn each knowledge source into documents.

One module per source, each exposing ``build_documents``. They share nothing but
that signature, because the three sources have nothing else in common: one is a
1.5 MB XML catalogue, one is a directory of Markdown, and one is a Python
literal.
"""
