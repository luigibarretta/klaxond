mod codes;
mod descriptor;

pub use codes::*;
pub use descriptor::{describe, ErrorDescriptor};

#[cfg(test)]
mod tests;
