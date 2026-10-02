//! RESOURCE-RECHECK 5+6: pressure uses CURRENT RSS (macOS `task_info`
//! resident_size; `ru_maxrss` reporting-only) and sustained rolling-core
//! excess throttles admission with hysteresis. Pure; no fixtures, no scan.

use repo_scan::config::ResourceLimits;
use repo_scan::scheduler::admission::{Admission, OpClass};
use repo_scan::telemetry::{rss_is_peak, FootprintSampler, SamplerInputs, Telemetry};

/// Item 5: RSS is current everywhere; macOS `ru_maxrss` rides along for
/// reporting only, never as the admission input.
#[test]
fn admit_current_rss_for_pressure_peak_for_reporting() {
    assert!(!rss_is_peak(), "RSS readings are current, not peak");
    let sampler = FootprintSampler::new();
    let sample = sampler.sample_with(&SamplerInputs::default());
    assert!(!sample.rss_is_peak);
    assert_eq!(sample.aggregate_rss_bytes, sample.owner_rss_bytes);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert!(sample.owner_rss_bytes > 0, "current owner RSS measured");
    #[cfg(target_os = "macos")]
    {
        let peak = sample
            .owner_peak_rss_bytes
            .expect("macOS retains ru_maxrss peak for reporting");
        assert!(peak > 0, "peak measured");
        assert!(peak >= sample.owner_rss_bytes, "peak {peak} floors current");
        let method = sampler.accounting_method();
        assert!(
            method.contains("peak") || method.contains("PEAK"),
            "{method}"
        );
        assert!(method.contains("reporting only"), "{method}");
        assert!(
            method.contains("task_info") && method.contains("resident_size"),
            "{method}"
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert_eq!(sample.owner_peak_rss_bytes, None);
        #[cfg(target_os = "linux")]
        {
            let method = sampler.accounting_method();
            assert!(
                method.contains("/proc/self/statm") && method.contains("current"),
                "{method}"
            );
        }
    }
}

/// Item 6: sustained excess throttles (reduced caps, no spawn, pacing,
/// halved prefetch); relief restores. Spikes and band samples hold state.
#[test]
fn admit_cpu_governor_hysteresis() {
    let mut admission = Admission::new(ResourceLimits::default());
    assert!(!admission.cpu_throttled());
    assert!(admission.pace_delay().is_zero());

    admission.observe_cpu(4.0); // one spike: not sustained
    assert!(!admission.cpu_throttled());
    admission.observe_cpu(1.05); // band sample breaks the streak
    admission.observe_cpu(4.0);
    admission.observe_cpu(4.0);
    assert!(!admission.cpu_throttled(), "non-consecutive overs hold");
    admission.observe_cpu(4.0); // third consecutive over: engage
    assert!(admission.cpu_throttled());
    assert!(!admission.pace_delay().is_zero());

    let first = admission
        .try_acquire(OpClass::Enumerate)
        .expect("first enum");
    assert!(admission.try_acquire(OpClass::Enumerate).is_none());
    assert!(admission.try_acquire(OpClass::GitProbe).is_none());
    assert!(!admission.helper_spawn_allowed());
    assert!(!admission.prefetch_allowed(600, 0), "halved prefetch cap");
    admission.release(&first);

    admission.observe_cpu(0.1); // single relief: no flap
    assert!(admission.cpu_throttled());
    admission.observe_cpu(1.05); // band breaks relief streak too
    assert!(admission.cpu_throttled());
    admission.observe_cpu(0.1);
    admission.observe_cpu(0.1);
    admission.observe_cpu(0.1); // third consecutive under: release
    assert!(!admission.cpu_throttled());
    assert!(admission.pace_delay().is_zero());
    assert!(admission.prefetch_allowed(600, 0));
    let e1 = admission.try_acquire(OpClass::Enumerate).expect("enum 1");
    let e2 = admission.try_acquire(OpClass::Enumerate).expect("enum 2");
    admission.release(&e1);
    admission.release(&e2);
}

/// Item 6: garbage CPU inputs count as zero, never engage the governor.
#[test]
fn admit_cpu_governor_ignores_garbage() {
    let mut admission = Admission::new(ResourceLimits::default());
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        admission.observe_cpu(bad);
    }
    assert!(!admission.cpu_throttled());
}
