//! Generic driver that runs a `round_based` protocol through its state machine and exchanges
//! serialized [`Envelope`]s with the caller

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cggmp21::progress::{Event, Tracer};
use round_based::rounds_router::ProtocolMessage;
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::Error;

/// Protocol message with routing information
///
/// `payload` is the CBOR encoding of the protocol message. The transport must authenticate
/// `sender` and keep p2p messages confidential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Index of the sending party
    pub sender: u16,
    /// Index of the receiving party, `None` for a broadcast message
    pub recipient: Option<u16>,
    /// Protocol round the message belongs to (informational, e.g. for statistics)
    pub round: u16,
    /// Serialized protocol message
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// Kind of a [`TraceEvent`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TraceKind {
    /// Protocol started
    ProtocolBegins,
    /// New round started
    RoundBegins,
    /// Named computation stage started
    Stage,
    /// Protocol waits for messages of the current round
    ReceiveMsgs,
    /// All messages of the current round received
    MsgsReceived,
    /// Protocol completed
    ProtocolEnds,
}

/// Progress event emitted by the protocol (no secret data)
#[derive(Debug, Clone, Serialize)]
pub struct TraceEvent {
    /// Timestamp in milliseconds: `performance.now()` on wasm, time since first use natively
    pub t: f64,
    /// Event kind
    pub kind: TraceKind,
    /// Name of the round or stage, if any
    pub name: Option<&'static str>,
}

/// Result of feeding a session
#[derive(Debug, Serialize)]
pub struct Step<O> {
    /// Messages to deliver
    pub outgoing: Vec<Envelope>,
    /// Progress events since the previous step
    pub events: Vec<TraceEvent>,
    /// Protocol output, present exactly once: in the step where the protocol completes
    pub output: Option<O>,
}

/// Milliseconds on a monotonic clock
#[cfg(target_arch = "wasm32")]
pub(crate) fn now_ms() -> f64 {
    crate::wasm::performance_now()
}

/// Milliseconds on a monotonic clock
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_ms() -> f64 {
    use std::sync::LazyLock;
    use std::time::Instant;
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_secs_f64() * 1000.
}

/// Collects tracer events of a running protocol
#[derive(Clone, Default)]
pub(crate) struct TraceLog(Arc<Mutex<Vec<TraceEvent>>>);

impl TraceLog {
    fn drain(&self) -> Vec<TraceEvent> {
        self.0
            .lock()
            .map(|mut events| std::mem::take(&mut *events))
            .unwrap_or_default()
    }
}

impl Tracer for TraceLog {
    fn trace_event(&mut self, event: Event) {
        let (kind, name) = match event {
            Event::ProtocolBegins => (TraceKind::ProtocolBegins, None),
            Event::RoundBegins { name } => (TraceKind::RoundBegins, name),
            Event::Stage { name } => (TraceKind::Stage, Some(name)),
            Event::ReceiveMsgs => (TraceKind::ReceiveMsgs, None),
            Event::MsgsReceived => (TraceKind::MsgsReceived, None),
            Event::ProtocolEnds => (TraceKind::ProtocolEnds, None),
            Event::SendMsg | Event::MsgSent => return,
        };
        if let Ok(mut events) = self.0.lock() {
            events.push(TraceEvent {
                t: now_ms(),
                kind,
                name,
            });
        }
    }
}

/// Type-erased protocol state machine with serialized messages
trait Machine<O> {
    /// Decodes a message and queues it until the protocol asks for it
    fn push(&mut self, id: u64, sender: u16, msg_type: MessageType, payload: &[u8]) -> bool;
    /// Runs the protocol until it needs a message that is not queued yet, or completes
    fn advance(&mut self, me: u16, outgoing: &mut Vec<Envelope>) -> Result<Option<O>, Error>;
}

struct Typed<M, S> {
    sm: S,
    inbox: VecDeque<Incoming<M>>,
    wants_msg: bool,
}

impl<M, S, O> Machine<O> for Typed<M, S>
where
    M: ProtocolMessage + Serialize + DeserializeOwned,
    S: StateMachine<Msg = M, Output = Result<O, Error>>,
{
    fn push(&mut self, id: u64, sender: u16, msg_type: MessageType, payload: &[u8]) -> bool {
        match ciborium::from_reader::<M, _>(payload) {
            Ok(msg) => {
                self.inbox.push_back(Incoming {
                    id,
                    sender,
                    msg_type,
                    msg,
                });
                true
            }
            Err(_) => false,
        }
    }

    fn advance(&mut self, me: u16, outgoing: &mut Vec<Envelope>) -> Result<Option<O>, Error> {
        loop {
            if self.wants_msg {
                let Some(msg) = self.inbox.pop_front() else {
                    return Ok(None);
                };
                self.sm
                    .received_msg(msg)
                    .map_err(|_| Error::Internal("state machine rejected a message"))?;
                self.wants_msg = false;
            }
            match self.sm.proceed() {
                ProceedResult::SendMsg(Outgoing { recipient, msg }) => {
                    let mut payload = Vec::new();
                    ciborium::into_writer(&msg, &mut payload)
                        .map_err(|_| Error::Internal("message serialization failed"))?;
                    outgoing.push(Envelope {
                        sender: me,
                        recipient: match recipient {
                            MessageDestination::AllParties => None,
                            MessageDestination::OneParty(j) => Some(j),
                        },
                        round: msg.round(),
                        payload,
                    });
                }
                ProceedResult::NeedsOneMoreMessage => self.wants_msg = true,
                ProceedResult::Yielded => {}
                ProceedResult::Output(output) => return output.map(Some),
                ProceedResult::Error(_) => {
                    return Err(Error::Internal("state machine execution failed"))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    NotStarted,
    Running,
    Finished,
    Failed,
}

/// Drives one party of one protocol run
pub(crate) struct Driver<O> {
    i: u16,
    n: u16,
    machine: Box<dyn Machine<O>>,
    trace: TraceLog,
    state: State,
    next_msg_id: u64,
}

impl<O> Driver<O> {
    /// `sm` must report progress into `trace`
    pub fn new<M, S>(i: u16, n: u16, trace: TraceLog, sm: S) -> Self
    where
        M: ProtocolMessage + Serialize + DeserializeOwned + 'static,
        S: StateMachine<Msg = M, Output = Result<O, Error>> + 'static,
        O: 'static,
    {
        Self {
            i,
            n,
            machine: Box::new(Typed {
                sm,
                inbox: VecDeque::new(),
                wants_msg: false,
            }),
            trace,
            state: State::NotStarted,
            next_msg_id: 0,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == State::Finished
    }

    pub fn start(&mut self) -> Result<Step<O>, Error> {
        if self.state != State::NotStarted {
            return Err(Error::Misuse("session already started"));
        }
        self.state = State::Running;
        self.advance()
    }

    /// Accepts a message addressed to this party
    ///
    /// Messages arriving before [`start`](Self::start) are queued. A rejected message (wrong
    /// recipient, unknown sender, undecodable payload) is reported as [`Error::InvalidMessage`]
    /// and does not terminate the session.
    pub fn handle_incoming(&mut self, envelope: &Envelope) -> Result<Step<O>, Error> {
        match self.state {
            State::Finished => return Err(Error::Misuse("session already finished")),
            State::Failed => return Err(Error::Misuse("session has failed")),
            State::NotStarted | State::Running => {}
        }
        let reject = |reason| Error::InvalidMessage {
            sender: envelope.sender,
            reason,
        };
        if envelope.sender >= self.n || envelope.sender == self.i {
            return Err(reject("invalid sender index"));
        }
        let msg_type = match envelope.recipient {
            None => MessageType::Broadcast,
            Some(j) if j == self.i => MessageType::P2P,
            Some(_) => return Err(reject("message is addressed to another party")),
        };
        if !self.machine.push(
            self.next_msg_id,
            envelope.sender,
            msg_type,
            &envelope.payload,
        ) {
            return Err(reject("malformed payload"));
        }
        self.next_msg_id += 1;
        if self.state == State::NotStarted {
            return Ok(Step {
                outgoing: Vec::new(),
                events: Vec::new(),
                output: None,
            });
        }
        self.advance()
    }

    fn advance(&mut self) -> Result<Step<O>, Error> {
        let mut outgoing = Vec::new();
        match self.machine.advance(self.i, &mut outgoing) {
            Ok(output) => {
                if output.is_some() {
                    self.state = State::Finished;
                }
                Ok(Step {
                    outgoing,
                    events: self.trace.drain(),
                    output,
                })
            }
            Err(err) => {
                self.state = State::Failed;
                Err(err)
            }
        }
    }
}
