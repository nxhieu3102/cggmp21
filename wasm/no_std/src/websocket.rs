#![allow(dead_code)]
extern crate alloc;

use alloc::string::String;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    type WebSocket;

    #[wasm_bindgen(constructor)]
    fn new(url: &str) -> WebSocket;

    #[wasm_bindgen(method, getter, js_name = clone)]
    fn clone(this: &WebSocket) -> WebSocket;

    #[wasm_bindgen(method, setter)]
    fn set_onopen(this: &WebSocket, callback: &Closure<dyn FnMut(JsValue)>);

    #[wasm_bindgen(method, setter)]
    fn set_onmessage(this: &WebSocket, callback: &Closure<dyn FnMut(JsValue)>);

    #[wasm_bindgen(method, setter)]
    fn set_onerror(this: &WebSocket, callback: &Closure<dyn FnMut(JsValue)>);

    #[wasm_bindgen(method, setter)]
    fn set_onclose(this: &WebSocket, callback: &Closure<dyn FnMut(JsValue)>);

    #[wasm_bindgen(method, catch)]
    fn send(this: &WebSocket, data: &str) -> Result<(), JsValue>;

    #[wasm_bindgen(method, catch)]
    fn close(this: &WebSocket) -> Result<(), JsValue>;

    #[wasm_bindgen(getter, method)]
    fn readyState(this: &WebSocket) -> u16;
}

// WebSocket ready states
const WS_CONNECTING: u16 = 0;
const WS_OPEN: u16 = 1;
const WS_CLOSING: u16 = 2;
const WS_CLOSED: u16 = 3;

#[wasm_bindgen]
pub struct WebSocketClient {
    ws: WebSocket,
    #[allow(dead_code)]
    on_open: Closure<dyn FnMut(JsValue)>,
    #[allow(dead_code)]
    on_message: Closure<dyn FnMut(JsValue)>,
    #[allow(dead_code)]
    on_error: Closure<dyn FnMut(JsValue)>,
    #[allow(dead_code)]
    on_close: Closure<dyn FnMut(JsValue)>,
}

#[wasm_bindgen]
impl WebSocketClient {
    #[wasm_bindgen(constructor)]
    pub fn new(url: &str) -> Result<WebSocketClient, JsValue> {
        let ws = WebSocket::new(url);
        
        // Create closures for WebSocket events
        let on_open = Closure::wrap(Box::new(move |_| {
            log("WebSocket connection established");
        }) as Box<dyn FnMut(JsValue)>);
        
        let on_message = Closure::wrap(Box::new(move |e: JsValue| {
            let data = js_sys::Reflect::get(&e, &JsValue::from_str("data"))
                .expect("event should have data");
            log(&format!("Received message: {:?}", data));
        }) as Box<dyn FnMut(JsValue)>);
        
        let on_error = Closure::wrap(Box::new(move |e: JsValue| {
            log(&format!("WebSocket error: {:?}", e));
        }) as Box<dyn FnMut(JsValue)>);
        
        let on_close = Closure::wrap(Box::new(move |e: JsValue| {
            log(&format!("WebSocket closed: {:?}", e));
        }) as Box<dyn FnMut(JsValue)>);
        
        // Set callbacks
        ws.set_onopen(&on_open);
        ws.set_onmessage(&on_message);
        ws.set_onerror(&on_error);
        ws.set_onclose(&on_close);
        
        Ok(WebSocketClient {
            ws,
            on_open,
            on_message,
            on_error,
            on_close,
        })
    }
    
    #[wasm_bindgen]
    pub fn send_message(&self, message: &str) -> Result<(), JsValue> {
        if self.ws.readyState() != WS_OPEN {
            return Err(JsValue::from_str("WebSocket is not open"));
        }
        self.ws.send(message)
    }
    
    #[wasm_bindgen]
    pub fn close(&self) -> Result<(), JsValue> {
        self.ws.close()
    }
    
    #[wasm_bindgen]
    pub fn is_open(&self) -> bool {
        self.ws.readyState() == WS_OPEN
    }
    
    #[wasm_bindgen]
    pub fn get_state(&self) -> u16 {
        self.ws.readyState()
    }
}

// Create a higher-level handler for P2P communication
#[wasm_bindgen]
pub struct P2PNode {
    party_id: u16,
    websocket: Option<WebSocket>,
    server_url: String,
    #[allow(dead_code)]
    on_open: Option<Closure<dyn FnMut(JsValue)>>,
    #[allow(dead_code)]
    on_message: Option<Closure<dyn FnMut(JsValue)>>,
    #[allow(dead_code)]
    on_error: Option<Closure<dyn FnMut(JsValue)>>,
    #[allow(dead_code)]
    on_close: Option<Closure<dyn FnMut(JsValue)>>,
    #[allow(dead_code)]
    message_callback: Option<JsValue>,
}

#[wasm_bindgen]
impl P2PNode {
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: u16, server_url: &str) -> Self {
        Self {
            party_id,
            websocket: None,
            server_url: String::from(server_url),
            on_open: None,
            on_message: None,
            on_error: None,
            on_close: None,
            message_callback: None,
        }
    }
    
    #[wasm_bindgen]
    pub fn connect(&mut self) -> Result<(), JsValue> {
        let party_id = self.party_id;
        let ws = WebSocket::new(&self.server_url);
        
        // Create a register message to send when connection opens
        let register_message = format!("REGISTER:{}", party_id);
        
        // Create open handler that sends a registration message
        let ws_clone = ws.clone();
        let on_open = Closure::wrap(Box::new(move |_| {
            log(&format!("WebSocket connection established for party {}", party_id));
            
            // Register the party ID with the server
            if let Err(e) = ws_clone.send(register_message.as_str()) {
                log(&format!("Error registering party ID: {:?}", e));
            } else {
                log(&format!("Registered as party {}", party_id));
            }
        }) as Box<dyn FnMut(JsValue)>);
        
        // Basic message, error and close handlers
        let message_callback_clone = self.message_callback.clone();
        let on_message = Closure::wrap(Box::new(move |e: JsValue| {
            if let Ok(data) = js_sys::Reflect::get(&e, &JsValue::from_str("data")) {
                if let Some(text) = data.as_string() {
                    // If we have a JS callback, call it
                    if let Some(callback) = &message_callback_clone {
                        let callback_clone = callback.clone();
                        let this = JsValue::null();
                        let args = js_sys::Array::of1(&JsValue::from_str(&text));
                        let _ = js_sys::Reflect::apply(
                            &callback_clone.dyn_into::<js_sys::Function>().unwrap(), 
                            &this, 
                            &args
                        );
                    } else {
                        // Otherwise just log the message
                        log(&format!("Received message: {}", text));
                    }
                }
            }
        }) as Box<dyn FnMut(JsValue)>);
        
        let on_error = Closure::wrap(Box::new(move |e: JsValue| {
            log(&format!("WebSocket error: {:?}", e));
        }) as Box<dyn FnMut(JsValue)>);
        
        let on_close = Closure::wrap(Box::new(move |e: JsValue| {
            log(&format!("WebSocket closed: {:?}", e));
        }) as Box<dyn FnMut(JsValue)>);
        
        // Set event handlers
        ws.set_onopen(&on_open);
        ws.set_onmessage(&on_message);
        ws.set_onerror(&on_error);
        ws.set_onclose(&on_close);
        
        // Store everything
        self.websocket = Some(ws);
        self.on_open = Some(on_open);
        self.on_message = Some(on_message);
        self.on_error = Some(on_error);
        self.on_close = Some(on_close);
        
        Ok(())
    }
    
    #[wasm_bindgen]
    pub fn set_message_handler(&mut self, handler: JsValue) {
        self.message_callback = Some(handler);
        
        // If we already have a websocket, update its message handler
        if let Some(ws) = &self.websocket {
            if let Some(callback) = &self.message_callback {
                let callback_clone = callback.clone();
                let on_message = Closure::wrap(Box::new(move |e: JsValue| {
                    if let Ok(data) = js_sys::Reflect::get(&e, &JsValue::from_str("data")) {
                        if let Some(text) = data.as_string() {
                            // Call the JS callback function with cloned callback
                            let cb_clone = callback_clone.clone();
                            let this = JsValue::null();
                            let args = js_sys::Array::of1(&JsValue::from_str(&text));
                            let _ = js_sys::Reflect::apply(
                                &cb_clone.dyn_into::<js_sys::Function>().unwrap(), 
                                &this, 
                                &args
                            );
                        }
                    }
                }) as Box<dyn FnMut(JsValue)>);
                
                ws.set_onmessage(&on_message);
                self.on_message = Some(on_message);
            }
        }
    }
    
    #[wasm_bindgen]
    pub fn send(&self, message: &str) -> Result<(), JsValue> {
        match &self.websocket {
            Some(ws) => {
                if ws.readyState() != WS_OPEN {
                    return Err(JsValue::from_str("WebSocket is not open"));
                }
                ws.send(message)
            },
            None => Err(JsValue::from_str("Not connected to WebSocket server")),
        }
    }
    
    #[wasm_bindgen]
    pub fn disconnect(&mut self) -> Result<(), JsValue> {
        match &self.websocket {
            Some(ws) => {
                let result = ws.close();
                self.websocket = None;
                self.on_open = None;
                self.on_message = None;
                self.on_error = None;
                self.on_close = None;
                result
            },
            None => Ok(()),
        }
    }
    
    #[wasm_bindgen]
    pub fn is_connected(&self) -> bool {
        match &self.websocket {
            Some(ws) => ws.readyState() == WS_OPEN,
            None => false,
        }
    }
    
    #[wasm_bindgen]
    pub fn get_party_id(&self) -> u16 {
        self.party_id
    }
} 
