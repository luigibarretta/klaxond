mod ntfy;
mod smtp;
mod telegram;

pub use ntfy::post_to_ntfy;
pub use smtp::post_to_smtp;
pub use telegram::post_to_telegram;

pub(crate) use ntfy::post_to_ntfy_with_config;
pub(crate) use smtp::post_to_smtp_with_config;
pub(crate) use telegram::post_to_telegram_with_config;
