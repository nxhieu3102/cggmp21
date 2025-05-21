/// Protocol execution ID
///
/// Each protocol execution must have unique execution ID. All signers taking part in the protocol
/// (keygen/signing/etc.) must share the same execution ID, otherwise protocol will abort with
/// unverbose error.
#[derive(Clone, Copy, Debug, udigest::Digestable)]
pub struct ExecutionId<'id> {
    #[udigest(as_bytes)]
    id: &'id [u8],
}

use alloc::boxed::Box;

impl<'id> ExecutionId<'id> {
    /// Constructs an execution ID from bytes
    pub fn new(eid: &'id [u8]) -> Self {
        Self { id: eid }
    }

    /// Constructs an execution ID from bytes with a static lifetime
    /// 
    /// This is useful for initializing protocol state that requires
    /// an execution ID with a 'static lifetime.
    pub fn new_static(eid: &[u8]) -> ExecutionId<'static> {
        // This requires converting the byte slice to a static reference
        // which is only safe if we're using a string literal or static data
        let static_bytes: &'static [u8] = Box::leak(eid.to_vec().into_boxed_slice());
        ExecutionId { id: static_bytes }
    }

    /// Returns bytes that represent an execution ID
    pub fn as_bytes(&self) -> &'id [u8] {
        self.id
    }
}
