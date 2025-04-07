use digest::Digest;
use generic_ec::Curve;
use round_based::ProtocolMessage;
use round_based::rounds_router::RoundMessage;

use crate::security_level::SecurityLevel;
use crate::threshold::{Msg as ThresholdMsg, MsgRound1 as ThresholdMsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3 as ThresholdMsgRound3, MsgReliabilityCheck as ThresholdMsgReliabilityCheck, THRESHOLD_ROUND_1, THRESHOLD_ROUND_2_BROAD, THRESHOLD_ROUND_2_UNI, THRESHOLD_ROUND_3, THRESHOLD_ROUND_RELIABILITY};
use crate::non_threshold::{Msg as NonThresholdMsg, MsgRound1 as NonThresholdMsgRound1, MsgRound2, MsgRound3 as NonThresholdMsgRound3, MsgReliabilityCheck as NonThresholdMsgReliabilityCheck, NON_THRESHOLD_ROUND_1, NON_THRESHOLD_ROUND_2, NON_THRESHOLD_ROUND_3, NON_THRESHOLD_ROUND_RELIABILITY};

// Implementation for Threshold Round 1 messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<ThresholdMsgRound1<D>> for ThresholdMsg<E, L, D> {
    const ROUND: u16 = THRESHOLD_ROUND_1;

    fn to_protocol_message(msg: ThresholdMsgRound1<D>) -> Self {
        Self::Round1(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<ThresholdMsgRound1<D>, Self> {
        match protocol_message {
            Self::Round1(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Threshold Round 2 Broadcast messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<MsgRound2Broad<E, L>> for ThresholdMsg<E, L, D> {
    const ROUND: u16 = THRESHOLD_ROUND_2_BROAD;

    fn to_protocol_message(msg: MsgRound2Broad<E, L>) -> Self {
        Self::Round2Broad(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<MsgRound2Broad<E, L>, Self> {
        match protocol_message {
            Self::Round2Broad(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Threshold Round 2 Unicast messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<MsgRound2Uni<E>> for ThresholdMsg<E, L, D> {
    const ROUND: u16 = THRESHOLD_ROUND_2_UNI;

    fn to_protocol_message(msg: MsgRound2Uni<E>) -> Self {
        Self::Round2Uni(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<MsgRound2Uni<E>, Self> {
        match protocol_message {
            Self::Round2Uni(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Threshold Round 3 messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<ThresholdMsgRound3<E>> for ThresholdMsg<E, L, D> {
    const ROUND: u16 = THRESHOLD_ROUND_3;

    fn to_protocol_message(msg: ThresholdMsgRound3<E>) -> Self {
        Self::Round3(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<ThresholdMsgRound3<E>, Self> {
        match protocol_message {
            Self::Round3(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Threshold Reliability check messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<ThresholdMsgReliabilityCheck<D>> for ThresholdMsg<E, L, D> {
    const ROUND: u16 = THRESHOLD_ROUND_RELIABILITY;

    fn to_protocol_message(msg: ThresholdMsgReliabilityCheck<D>) -> Self {
        Self::ReliabilityCheck(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<ThresholdMsgReliabilityCheck<D>, Self> {
        match protocol_message {
            Self::ReliabilityCheck(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Non-threshold implementations

// Implementation for Non-threshold Round 1 messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<NonThresholdMsgRound1<D>> for NonThresholdMsg<E, L, D> {
    const ROUND: u16 = NON_THRESHOLD_ROUND_1;

    fn to_protocol_message(msg: NonThresholdMsgRound1<D>) -> Self {
        Self::Round1(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<NonThresholdMsgRound1<D>, Self> {
        match protocol_message {
            Self::Round1(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Non-threshold Round 2 messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<MsgRound2<E, L>> for NonThresholdMsg<E, L, D> {
    const ROUND: u16 = NON_THRESHOLD_ROUND_2;

    fn to_protocol_message(msg: MsgRound2<E, L>) -> Self {
        Self::Round2(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<MsgRound2<E, L>, Self> {
        match protocol_message {
            Self::Round2(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Non-threshold Round 3 messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<NonThresholdMsgRound3<E>> for NonThresholdMsg<E, L, D> {
    const ROUND: u16 = NON_THRESHOLD_ROUND_3;

    fn to_protocol_message(msg: NonThresholdMsgRound3<E>) -> Self {
        Self::Round3(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<NonThresholdMsgRound3<E>, Self> {
        match protocol_message {
            Self::Round3(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
}

// Implementation for Non-threshold Reliability check messages
impl<E: Curve, L: SecurityLevel, D: Digest> RoundMessage<NonThresholdMsgReliabilityCheck<D>> for NonThresholdMsg<E, L, D> {
    const ROUND: u16 = NON_THRESHOLD_ROUND_RELIABILITY;

    fn to_protocol_message(msg: NonThresholdMsgReliabilityCheck<D>) -> Self {
        Self::ReliabilityCheck(msg)
    }

    fn from_protocol_message(protocol_message: Self) -> Result<NonThresholdMsgReliabilityCheck<D>, Self> {
        match protocol_message {
            Self::ReliabilityCheck(msg) => Ok(msg),
            _ => Err(protocol_message),
        }
    }
} 
