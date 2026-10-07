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

/// Time a responder has to answer a confirmed request, measured from the request's last transmission.
pub const RESPONSE_WINDOW: Duration = Duration::from_secs(10);

/// Confirmed requests a device must have received before its silence is judged.
pub const UNRESPONSIVE_MIN_REQUESTS: u64 = 10;

/// Answered share of received requests below which a device is Medium.
pub const UNRESPONSIVE_MEDIUM_BELOW: f64 = 0.50;

/// Answered share of received requests below which a device is High.
pub const UNRESPONSIVE_HIGH_BELOW: f64 = 0.20;

/// Gap in sightings of one forwarded broadcast after which it counts as a new broadcast. Forwarders
/// relaying the same bytes further apart than this are not duplicate BBMDs: periodic broadcasts
/// repeat byte for byte.
pub const FORWARD_DUPLICATE_WINDOW: Duration = Duration::from_secs(60);

/// Distinct forwarding IPs relaying one broadcast at which BBMDs count as duplicates.
pub const FORWARD_DUPLICATE_FORWARDERS: usize = 2;

/// Distinct forwarding IPs relaying one broadcast at which duplicate BBMDs are Critical.
pub const FORWARD_CRITICAL_FORWARDERS: usize = 3;

/// Sightings of one forwarded broadcast, in one bucket, above which the forwarding-loop trigger fires.
pub const FORWARD_LOOP_PER_BUCKET: u64 = 5;

/// Sightings of one forwarded broadcast, in one bucket, above which a forwarding loop is Critical.
pub const FORWARD_LOOP_CRITICAL_PER_BUCKET: u64 = 20;

/// Broadcasts sent by local hosts that must be seen before their never being relayed back is
/// read as a missing BDT entry. A message-count floor only: the rule is not a rate rule.
pub const INCOMPLETE_BDT_MIN_LOCAL_BROADCASTS: u64 = 50;

/// Time a BBMD has to NAK a registration, measured from the Register-Foreign-Device request.
pub const REGISTRATION_NAK_WINDOW: Duration = Duration::from_secs(10);

/// NAKs for one registrant above which a registration failure is High.
pub const REGISTRATION_NAK_HIGH_ABOVE: u64 = 5;

/// Silence after the last segment of a segmented exchange, with no final segment, abort or
/// reject, after which the exchange counts as abandoned.
pub const SEGMENT_ABANDON_AFTER: Duration = Duration::from_secs(30);

/// Abandoned exchanges for one (sender, receiver) pair at which segmentation misuse is reported.
pub const SEGMENT_ABANDONED_MIN: u64 = 3;

/// Judged exchanges for one pair that must exist before the abandonment ratio is read.
pub const SEGMENT_RATIO_MIN_EXCHANGES: u64 = 10;

/// Abandoned share of a pair's judged exchanges above which segmentation misuse is High.
pub const SEGMENT_HIGH_ABOVE_SHARE: f64 = 0.50;
