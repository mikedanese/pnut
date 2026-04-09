//! Capability dropping for the sandbox.

use crate::error::Error;

pub use caps::Capability;

/// Linux capabilities to keep after dropping all others.
#[derive(Debug, Default)]
pub struct Config {
    pub keep: Vec<Capability>,
}

impl Config {
    /// Keep one capability after dropping all others.
    pub fn keep(&mut self, capability: Capability) -> &mut Self {
        self.keep.push(capability);
        self
    }
}

/// Apply capability restrictions: drop everything not in the keep list.
pub(crate) fn apply_capabilities(config: &Config) -> Result<(), Error> {
    let keep_caps: caps::CapsHashSet = config.keep.iter().copied().collect();

    caps::clear(None, caps::CapSet::Ambient).map_err(|e| {
        Error::Other(format!(
            "capabilities: failed to clear Ambient capability set: {e}"
        ))
    })?;

    for cap in caps::all() {
        if !keep_caps.contains(&cap) {
            let _ = caps::drop(None, caps::CapSet::Bounding, cap);
        }
    }

    caps::set(None, caps::CapSet::Effective, &keep_caps).map_err(|e| {
        Error::Other(format!(
            "capabilities: failed to set Effective capability set: {e}"
        ))
    })?;
    caps::set(None, caps::CapSet::Inheritable, &keep_caps).map_err(|e| {
        Error::Other(format!(
            "capabilities: failed to set Inheritable capability set: {e}"
        ))
    })?;
    caps::set(None, caps::CapSet::Permitted, &keep_caps).map_err(|e| {
        Error::Other(format!(
            "capabilities: failed to set Permitted capability set: {e}"
        ))
    })?;

    Ok(())
}
