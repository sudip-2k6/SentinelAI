from bisect import bisect_right
from dataclasses import dataclass
from math import isfinite, log

_EULER = 0.5772156649015329


def correction(size: int) -> float:
    if size <= 1:
        return 0.0
    if size == 2:
        return 1.0
    return 2 * (log(size - 1) + _EULER) - 2 * (size - 1) / size


@dataclass(slots=True)
class Forest:
    trees: list[list[list]]
    sample_size: int
    reference: list[float]

    def raw(self, vector: list[float]) -> float:
        total = 0.0
        for tree in self.trees:
            index = 0
            for depth in range(len(tree)):
                left, right, feature, threshold, samples = tree[index]
                if left == -1:
                    total += depth + correction(samples)
                    break
                index = left if vector[feature] <= threshold else right
        return 2 ** (-total / (len(self.trees) * correction(self.sample_size)))

    def percentile(self, vector: list[float]) -> float:
        return bisect_right(self.reference, self.raw(vector)) / len(self.reference)

    def to_json(self) -> dict:
        return {"trees": self.trees, "sample_size": self.sample_size, "reference": self.reference}

    @classmethod
    def from_json(cls, value: dict, dimensions: int) -> "Forest":
        trees, size, reference = value["trees"], value["sample_size"], value["reference"]
        if (
            type(size) is not int
            or not 2 <= size <= 1024
            or not isinstance(trees, list)
            or not 1 <= len(trees) <= 128
            or not isinstance(reference, list)
            or not 1 <= len(reference) <= 4096
            or any(type(x) not in (int, float) or not 0 <= x <= 1 for x in reference)
            or sorted(reference) != reference
        ):
            raise ValueError("Malformed anomaly forest metadata.")
        for tree in trees:
            if not isinstance(tree, list) or not 1 <= len(tree) <= 2047:
                raise ValueError("Malformed anomaly tree.")
            for index, node in enumerate(tree):
                if not isinstance(node, list) or len(node) != 5:
                    raise ValueError("Malformed anomaly node.")
                left, right, feature, threshold, samples = node
                if (
                    any(type(x) is not int for x in (left, right, feature, samples))
                    or type(threshold) not in (int, float)
                    or not isfinite(threshold)
                    or not 1 <= samples <= size
                ):
                    raise ValueError("Invalid anomaly node.")
                if (left, right) != (-1, -1) and not (
                    index < left < right < len(tree) and 0 <= feature < dimensions
                ):
                    raise ValueError("Invalid anomaly tree edges.")
        return cls(trees, size, reference)
