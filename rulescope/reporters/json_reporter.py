from __future__ import annotations

"""JSON reporter — serializes the full CatalogReport as structured JSON."""

import json


class JsonReporter:
    def render(self, report) -> str:
        return json.dumps(report.model_dump(), indent=2, ensure_ascii=False)
