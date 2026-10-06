//! Every detector's tuning numbers, one named and documented constant each (wayfinder ticket #4).
//! Fixture calibration may move a value; it never changes a rule's shape.

use std::time::Duration;

/// Distinct source IPs at which a duplicate device ID becomes Critical.
pub const DUPLICATE_ID_CRITICAL_IPS: usize = 3;

/// Shortest capture span a rate-based rule needs before it may fire.
pub const RATE_RULE_MIN_SPAN: Duration = Duration::from_secs(5 * 60);

/// Width of the fixed buckets that storm-class rules measure peak rate over.
pub const RATE_BUCKET: Duration = Duration::from_secs(60);

/// Global Who-Is per second, in one bucket, above which the Who-Is flood trigger fires.
pub const WHO_IS_FLOOD_PER_SEC: u64 = 10;

/// Broadcast I-Am per second, in one bucket, above which the I-Am flood trigger fires.
pub const I_AM_FLOOD_PER_SEC: u64 = 50;

/// Broadcast share of decoded BACnet messages above which the saturation trigger fires.
pub const BROADCAST_SATURATION_SHARE: f64 = 0.30;

/// Decoded BACnet messages the saturation trigger needs before it may fire.
pub const BROADCAST_SATURATION_MIN_MESSAGES: u64 = 200;

/// Broadcasting source addresses above which a storm is Critical.
pub const STORM_CRITICAL_SOURCES: usize = 25;

/// Broadcast share above which a storm is Critical.
pub const STORM_CRITICAL_SHARE: f64 = 0.50;

/// Undecodable/non-BACnet share of the capture above which a storm finding tells the engineer to
/// verify the storm is BACnet-sourced. Lower than the capture-health threshold: it is a caution,
/// not a verdict on the whole report.
pub const STORM_UNDECODABLE_NOTE_SHARE: f64 = 0.25;

/// Top talkers a storm finding names.
pub const STORM_TOP_TALKERS: usize = 5;
