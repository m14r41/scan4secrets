"""Extract embedded source code from JS source-map files."""

import json
from typing import Iterable, Tuple


def extract_from_sourcemap(text: str) -> Iterable[Tuple[str, str]]:
    """Yield (source_name, source_text) tuples from a v3 source map."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    for i, src in enumerate(contents):
        if not isinstance(src, str):
            continue
        name = sources[i] if i < len(sources) else f"source[{i}]"
        yield name, src
