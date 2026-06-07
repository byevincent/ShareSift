"""Structured config-file parsers — credential extractors.

Inspired by NetSPI PowerHuntShares 2.0's named-field parsers. Each
parser takes file content and yields extracted credential fields as
``(field_name, value, confidence)`` tuples. Higher precision than the
generic regex content rules for the file formats they cover.

A dispatch map keys parser functions by filename glob, so a single
entry point ``parse_file(name, content)`` routes to the right one.
"""

from sharesift.parsers.dispatch import (
    parse_file,
    parsers,
    ExtractedField,
)

__all__ = ["parse_file", "parsers", "ExtractedField"]
