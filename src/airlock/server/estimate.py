"""Analysis time model: seconds per binary = fixed overhead + code MB x rate.

The overhead covers import, extraction and linking and dominates small DLLs; the rate covers the
auto-analysis of the code. Both start as configured priors and are refined from the binaries
already measured in the project.
"""

from __future__ import annotations

MB = 1 << 20
PRIOR_WEIGHT_MB = 0.5   # weight of the rate prior, in MB of code, against few samples
MIN_FIT_SAMPLES = 3     # least squares needs at least this many measured binaries
MIN_SPREAD_MB = 0.05    # ... and sizes that differ at least this much (standard deviation)
RUNNING_FLOOR = 0.25    # a running binary always shows at least this share of its estimate


def binary_seconds(code_bytes: float, overhead_s: float, rate: float) -> float:
    return overhead_s + code_bytes / MB * rate


def refine(samples: list[tuple[float, float]], prior_overhead: float,
           prior_rate: float) -> tuple[float, float]:
    """(overhead_s, s_per_mb) from measured (code MB, seconds) samples and the priors."""
    samples = [(mb, s) for mb, s in samples if s > 0 and mb >= 0]
    n = len(samples)
    if n == 0:
        return prior_overhead, prior_rate
    mean_mb = sum(m for m, _ in samples) / n
    mean_s = sum(s for _, s in samples) / n
    sxx = sum((m - mean_mb) ** 2 for m, _ in samples)
    if n >= MIN_FIT_SAMPLES and (sxx / n) ** 0.5 >= MIN_SPREAD_MB:
        slope = sum((m - mean_mb) * (s - mean_s) for m, s in samples) / sxx
        icpt = mean_s - slope * mean_mb
        if slope > 0 and icpt >= 0:
            return icpt, slope
        if slope > 0:  # negative intercept: fit through the origin, no fixed cost
            sxy = sum(m * s for m, s in samples)
            sxx0 = sum(m * m for m, _ in samples)
            return 0.0, max(sxy / sxx0, 1e-6)
    # few or uniform samples: overhead from the residuals against the prior rate (one prior
    # sample), then the rate from what the overhead leaves over (prior weighs PRIOR_WEIGHT_MB)
    over = sum(max(s - prior_rate * m, 0.0) for m, s in samples)
    overhead = (prior_overhead + over) / (1 + n)
    secs = sum(max(s - overhead, 0.0) for _, s in samples)
    mb = sum(m for m, _ in samples)
    return overhead, (prior_rate * PRIOR_WEIGHT_MB + secs) / (PRIOR_WEIGHT_MB + mb)


def priors(defaults: dict) -> tuple[float, float]:
    """(analysis_overhead_s, analysis_s_per_code_mb) from the config values."""
    oh = defaults.get("analysis_overhead_s")
    return (float(oh) if oh is not None else 20.0,
            float(defaults.get("analysis_s_per_code_mb") or 120.0))
