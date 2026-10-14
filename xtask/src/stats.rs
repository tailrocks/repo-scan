//! Deterministic seeded statistics for the proof runner.
//!
//! The RNG is SplitMix64 so paired-block order and bootstrap resampling are
//! reproducible from the seed recorded in the run manifest. Bootstrap bounds
//! use the nearest-rank percentile over a fixed number of resamples.

/// SplitMix64 PRNG (deterministic, seedable, no external crates).
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in [0, n). n must be > 0.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

pub fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

pub fn geomean(xs: &[f64]) -> f64 {
    let log_sum: f64 = xs.iter().map(|x| x.ln()).sum();
    (log_sum / xs.len() as f64).exp()
}

/// Nearest-rank upper percentile of the bootstrap distribution of `stat`.
fn bootstrap_upper_bound(
    stat: &mut dyn FnMut(&mut SplitMix64) -> f64,
    resamples: usize,
    confidence: f64,
    seed: u64,
) -> f64 {
    let mut rng = SplitMix64::new(seed);
    let mut values = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        values.push(stat(&mut rng));
    }
    values.sort_by(f64::total_cmp);
    let idx = ((confidence * resamples as f64).ceil() as usize).clamp(1, resamples) - 1;
    values[idx]
}

/// Seeded bootstrap one-sided upper confidence bound on the mean of paired
/// block ratios (candidate elapsed / baseline elapsed).
pub fn bootstrap_mean_u95(ratios: &[f64], resamples: usize, confidence: f64, seed: u64) -> f64 {
    bootstrap_upper_bound(
        &mut |rng| {
            let mut sum = 0.0;
            for _ in 0..ratios.len() {
                sum += ratios[rng.below(ratios.len())];
            }
            sum / ratios.len() as f64
        },
        resamples,
        confidence,
        seed,
    )
}

/// Seeded bootstrap one-sided upper confidence bound on the equal-weight
/// geometric mean of per-scenario mean ratios. Blocks are resampled jointly
/// within each scenario so the bound is simultaneous across the suite.
pub fn bootstrap_geomean_u95(
    groups: &[Vec<f64>],
    resamples: usize,
    confidence: f64,
    seed: u64,
) -> f64 {
    bootstrap_upper_bound(
        &mut |rng| {
            let mut log_sum = 0.0;
            for g in groups {
                let mut sum = 0.0;
                for _ in 0..g.len() {
                    sum += g[rng.below(g.len())];
                }
                log_sum += (sum / g.len() as f64).ln();
            }
            (log_sum / groups.len() as f64).exp()
        },
        resamples,
        confidence,
        seed,
    )
}

/// Seeded joint bootstrap simultaneous upper confidence bounds across a family
/// of gate scenarios. For K gates, block ratios are resampled jointly across all
/// scenarios per iteration, deriving a simultaneous (1 - alpha) bound.
#[allow(clippy::needless_range_loop)]
pub fn bootstrap_joint_family_u95(
    families: &[&[f64]],
    resamples: usize,
    confidence: f64,
    seed: u64,
) -> Vec<f64> {
    let k = families.len();
    if k == 0 {
        return Vec::new();
    }
    if k == 1 {
        return vec![bootstrap_mean_u95(families[0], resamples, confidence, seed)];
    }

    let mut rng = SplitMix64::new(seed);
    // Matrix of resampled means: [gate][resample]
    let mut means: Vec<Vec<f64>> = vec![Vec::with_capacity(resamples); k];
    for _ in 0..resamples {
        for (idx, ratios) in families.iter().enumerate() {
            let n = ratios.len();
            let mut sum = 0.0;
            for _ in 0..n {
                sum += ratios[rng.below(n)];
            }
            means[idx].push(sum / n as f64);
        }
    }

    // Sorted copies for each gate to compute empirical percentiles
    let mut sorted_means: Vec<Vec<f64>> = means.clone();
    for row in &mut sorted_means {
        row.sort_by(f64::total_cmp);
    }

    // Compute empirical percentile rank of each sample in each gate
    let mut max_ranks = Vec::with_capacity(resamples);
    for b in 0..resamples {
        let mut max_r: f64 = 0.0;
        for (g, s_means) in sorted_means.iter().enumerate().take(k) {
            let val = means[g][b];
            let pos = match s_means.binary_search_by(|v| v.total_cmp(&val)) {
                Ok(p) => p,
                Err(p) => p,
            };
            let rank = (pos + 1) as f64 / resamples as f64;
            if rank > max_r {
                max_r = rank;
            }
        }
        max_ranks.push(max_r);
    }
    max_ranks.sort_by(f64::total_cmp);

    let idx = ((confidence * resamples as f64).ceil() as usize).clamp(1, resamples) - 1;
    let gamma = max_ranks[idx];

    // Compute the gamma-percentile for each gate as its simultaneous bound
    let gamma_idx = ((gamma * resamples as f64).ceil() as usize).clamp(1, resamples) - 1;
    let mut bounds = Vec::with_capacity(k);
    for s_means in sorted_means.iter().take(k) {
        bounds.push(s_means[gamma_idx]);
    }
    bounds
}
