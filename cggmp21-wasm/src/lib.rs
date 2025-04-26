use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use rand::Rng;
use std::cell::RefCell;

// Export the keygen module for WASM
pub mod keygen;

// Define the message format
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub sender: String,
    pub round: u8,
    pub data: u32,
}

// Protocol state struct
#[wasm_bindgen]
pub struct Protocol {
    party_id: String,
    own_number: RefCell<Option<u32>>,
}

#[wasm_bindgen]
impl Protocol {
    // Initialize the protocol with a party identifier
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: String) -> Protocol {
        console_error_panic_hook::set_once();
        Protocol {
            party_id,
            own_number: RefCell::new(None),
        }
    }

    // Round 1: Generate random number and create message
    pub fn run_round_1(&self) -> JsValue {
        // Generate random number between 1 and 100
        let random_num = rand::thread_rng().gen_range(1..=100);
        
        // Store own number
        *self.own_number.borrow_mut() = Some(random_num);
        
        // Create message for round 1
        let message = Message {
            sender: self.party_id.clone(),
            round: 1,
            data: random_num,
        };
        
        // Convert to JsValue and return
        serde_wasm_bindgen::to_value(&message).unwrap()
    }

    // Round 2: Compute sum of all numbers
    pub fn run_round_2(&self, messages_js: JsValue) -> u32 {
        // Parse incoming messages
        let messages: Vec<Message> = serde_wasm_bindgen::from_value(messages_js).unwrap_or_else(|_| vec![]);
        
        // Get own number
        let own_num = self.own_number.borrow().unwrap_or(0);
        
        // Calculate sum of all numbers (including own)
        let sum = messages.iter().map(|msg| msg.data).sum::<u32>() + own_num;
        
        sum
    }

    // Helper function to get party ID
    pub fn get_party_id(&self) -> String {
        self.party_id.clone()
    }
    
    // Helper function to get own number
    pub fn get_own_number(&self) -> Option<u32> {
        *self.own_number.borrow()
    }
}

// Function to create a message for testing or specific scenarios
#[wasm_bindgen]
pub fn create_message(sender: String, round: u8, data: u32) -> JsValue {
    let message = Message {
        sender,
        round,
        data,
    };
    serde_wasm_bindgen::to_value(&message).unwrap()
}

// Tests for the protocol
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_run_round_1() {
        let protocol = Protocol::new("test_party".to_string());
        let message_js = protocol.run_round_1();
        let message: Message = serde_wasm_bindgen::from_value(message_js).unwrap();
        
        assert_eq!(message.sender, "test_party");
        assert_eq!(message.round, 1);
        assert!(message.data >= 1 && message.data <= 100);
        
        // Check that the number was stored in the protocol state
        let own_number = protocol.get_own_number().unwrap();
        assert_eq!(own_number, message.data);
    }

    #[wasm_bindgen_test]
    fn test_run_round_2() {
        let protocol = Protocol::new("test_party".to_string());
        
        // Set own number
        *protocol.own_number.borrow_mut() = Some(42);
        
        // Create test messages from other parties
        let messages = vec![
            Message { sender: "party1".to_string(), round: 1, data: 10 },
            Message { sender: "party2".to_string(), round: 1, data: 20 },
            Message { sender: "party3".to_string(), round: 1, data: 30 },
        ];
        
        let messages_js = serde_wasm_bindgen::to_value(&messages).unwrap();
        let sum = protocol.run_round_2(messages_js);
        
        // Expected sum: 10 + 20 + 30 + 42 = 102
        assert_eq!(sum, 102);
    }
}
