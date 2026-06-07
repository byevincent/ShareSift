"""Pre-processing hooks that run before content rules see file bytes.

Each preprocessor takes raw file bytes/text and emits expanded content
that gets scanned by rules — e.g. base64 decode of embedded blobs,
zip extraction of archives, etc.
"""

from sharesift.preprocess.base64_decode import recursive_base64_decode

__all__ = ["recursive_base64_decode"]
