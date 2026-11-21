import math
from collections.abc import Mapping
from dataclasses import dataclass

from app.core.contracts import Analysis
from app.features.common import normalized_histogram
from app.ml.rich_features import (
    COMMON_NAMES,
    ELF_NAMES,
    EXTRA_COMMON_NAMES,
    EXTRA_ELF_NAMES,
    PE_NAMES,
    PE_WIDE_NAMES,
    live_vector,
)


@dataclass(frozen=True, slots=True)
class Schema:
    id: str
    format: str
    features: tuple[str, ...]

    @property
    def columns(self) -> list[str]:
        return [f"f{index:03d}" for index in range(len(self.features))]


HISTOGRAM_FEATURES = (
    "File size (bytes)",
    *(f"Byte frequency 0x{index:02X}" for index in range(256)),
)
PE = Schema("pe-ember-histogram-v1", "PE", HISTOGRAM_FEATURES)
ELF_HISTOGRAM = Schema("elf-ember-histogram-v1", "ELF", HISTOGRAM_FEATURES)
PE_RICH = Schema("pe-ember-static-v2", "PE", HISTOGRAM_FEATURES + COMMON_NAMES + PE_NAMES)
ELF_RICH = Schema("elf-ember-static-v2", "ELF", HISTOGRAM_FEATURES + COMMON_NAMES + ELF_NAMES)
PE_PRECISION = Schema(
    "pe-ember-static-v3",
    "PE",
    HISTOGRAM_FEATURES + COMMON_NAMES + EXTRA_COMMON_NAMES + PE_WIDE_NAMES,
)
ELF_PRECISION = Schema(
    "elf-ember-static-v3",
    "ELF",
    HISTOGRAM_FEATURES + COMMON_NAMES + EXTRA_COMMON_NAMES + ELF_NAMES + EXTRA_ELF_NAMES,
)
ELF = Schema(
    "elf-static-v1",
    "ELF",
    (
        "File size (bytes)",
        "File entropy",
        "ELF class (bits)",
        "Program header count",
        "Section count",
        "Executable sections",
        "Writable sections",
        "Executable writable sections",
        "Mean section entropy",
        "Maximum section entropy",
        "Recorded library dependencies",
    ),
)
SCHEMAS = {schema.format: schema for schema in (PE, ELF)}
SCHEMAS_BY_ID = {
    schema.id: schema
    for schema in (PE, ELF, ELF_HISTOGRAM, PE_RICH, ELF_RICH, PE_PRECISION, ELF_PRECISION)
}


def extract(data: bytes, analysis: Analysis, schema: Schema | None = None) -> list[float]:
    schema = schema or SCHEMAS.get(analysis.format)
    if schema is None or analysis.format != schema.format:
        raise ValueError("No compatible executable feature schema.")
    if schema in (PE, ELF_HISTOGRAM):
        return [len(data), *normalized_histogram(data)]
    if schema in (PE_RICH, ELF_RICH):
        return [len(data), *normalized_histogram(data), *live_vector(data, analysis)]
    if schema in (PE_PRECISION, ELF_PRECISION):
        return [len(data), *normalized_histogram(data), *live_vector(data, analysis, enhanced=True)]
    if schema != ELF:
        raise ValueError("No compatible executable feature schema.")
    sections = analysis.sections
    entropies = [float(item["entropy"]) for item in sections]
    return [
        len(data),
        analysis.entropy,
        float(analysis.headers["Architecture"]),
        float(analysis.headers["Program headers"]),
        len(sections),
        sum(bool(item["executable"]) for item in sections),
        sum(bool(item["writable"]) for item in sections),
        sum(bool(item["executable"] and item["writable"]) for item in sections),
        sum(entropies) / len(entropies) if entropies else 0.0,
        max(entropies, default=0.0),
        len(analysis.imports),
    ]


def numeric_vector(values: object, schema: Schema) -> list[float]:
    if isinstance(values, Mapping):
        if set(values) != set(schema.features):
            raise ValueError("Feature names do not match the declared schema.")
        values = [values[name] for name in schema.features]
    if not isinstance(values, list) or len(values) != len(schema.features):
        raise ValueError("Feature vector length does not match the declared schema.")
    if any(type(value) not in (float, int) for value in values):
        raise ValueError("Features must be numeric.")
    floats = [float(value) for value in values]
    if any(not math.isfinite(value) or abs(value) > 1e15 for value in floats):
        raise ValueError("Non-finite or excessive input features.")
    return floats
