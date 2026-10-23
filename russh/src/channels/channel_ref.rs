use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use super::{DrainSignal, WindowSizeRef};
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
    pub(super) drain_signal: Option<Arc<DrainSignal>>,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
            drain_signal: None,
        }
    }

    /// A handle whose queue the session delivers to, so it must be able to
    /// wake the session when the application makes room again.
    pub(crate) fn new_for_session(
        sender: Sender<ChannelMsg>,
        drain_signal: Arc<DrainSignal>,
    ) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
            drain_signal: Some(drain_signal),
        }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }

    pub(crate) fn drain_signal(&self) -> Option<&Arc<DrainSignal>> {
        self.drain_signal.as_ref()
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
