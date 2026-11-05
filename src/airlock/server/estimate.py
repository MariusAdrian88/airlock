"""Analysis time model: seconds per binary = fixed overhead + work MB x rate.

The overhead covers import, extraction and linking and dominates small DLLs; the rate covers the
auto-analysis. "Work MB" is the light scan's estimate of the function count expressed in MB of
typical code (`FUNCS_PER_MB` functions per MB), because analysis time follows the number of
functions more closely than the code size. Entries without a function estimate use their code MB.

Both parameters start as configured priors and are refined from the binaries already measured in
the project by a blend with the prior, so one binary cannot swing the model.
"""

from __future__ import annotations

MB = 1 << 20
FUNCS_PER_MB = 9000.0   # typical functions per MB of code; converts a function count to work MB
PRIOR_WEIGHT_MB = 1.0   # weight of the rate prior, in work MB, against the measured binaries
OVERHEAD_WEIGHT = 2.0   # weight of the overhead prior, in binaries
OVERHEAD_SCALE_MB = 0.2  # a binary this big counts half as evidence for the overhead
RATE_BOUNDS = (0.4, 2.5)  # the refined rate stays within these multiples of the prior
OVERHEAD_BOUNDS = (0.25, 4.0)  # ... and the refined overhead likewise
RUNNING_FLOOR = 0.25    # a running binary always shows at least this share of its estimate


def work_mb(code_bytes: float, funcs: float = 0) -> float:
    """Analysis work of one binary in MB: from the estimated function count, else the code size."""
    if funcs and funcs > 0:
        return funcs / FUNCS_PER_MB
    return max(code_bytes, 0) / MB


def binary_seconds(work: float, overhead_s: float, rate: float) -> float:
    return overhead_s + work * rate


def refine(samples: list[tuple[float, float]], prior_overhead: float,
           prior_rate: float) -> tuple[float, float]:
    """(overhead_s, s_per_work_mb) from measured (work MB, seconds) samples and the priors.

    The overhead is the prior averaged with what each sample leaves over at the prior rate, small
    binaries counting most. The rate is the prior (worth PRIOR_WEIGHT_MB) averaged with the seconds
    the samples spent beyond the overhead per work MB."""
    samples = [(w, s) for w, s in samples if s > 0 and w >= 0]
    if not samples:
        return prior_overhead, prior_rate
    oh_lo, oh_hi = (prior_overhead * k for k in OVERHEAD_BOUNDS)
    num, den = prior_overhead * OVERHEAD_WEIGHT, OVERHEAD_WEIGHT
    for w, s in samples:
        e = 1.0 / (1.0 + w / OVERHEAD_SCALE_MB)
        num += e * min(max(s - prior_rate * w, 0.0), oh_hi)
        den += e
    overhead = min(max(num / den, oh_lo), oh_hi) if prior_overhead > 0 else 0.0
    secs = sum(max(s - overhead, 0.0) for _, s in samples)
    total_w = sum(w for w, _ in samples)
    rate = (prior_rate * PRIOR_WEIGHT_MB + secs) / (PRIOR_WEIGHT_MB + total_w)
    lo, hi = (prior_rate * k for k in RATE_BOUNDS)
    return overhead, min(max(rate, lo), hi)


def priors(defaults: dict) -> tuple[float, float]:
    """(analysis_overhead_s, analysis_s_per_code_mb) from the config values."""
    oh = defaults.get("analysis_overhead_s")
    return (float(oh) if oh is not None else 6.0,
            float(defaults.get("analysis_s_per_code_mb") or 170.0))
