mod routing;
mod timeline;
mod validation;

pub use routing::{EmergencyRoutingDecision, select_emergency_profile};
pub use timeline::{EmergencyTimelineEvent, emergency_timeline};
pub use validation::validate_emergency_config;

#[cfg(test)]
mod tests;
