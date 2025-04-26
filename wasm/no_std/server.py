import http.server
import socketserver
import asyncio
import websockets
import threading

PORT = 8090
WS_PORT = 8091  # Separate port for WebSocket

class WasmHandler(http.server.SimpleHTTPRequestHandler):
    # Define MIME types for different file extensions
    mime_types = {
        '.wasm': 'application/wasm',
        '.js': 'text/javascript',
        '.html': 'text/html',
        '.css': 'text/css',
        '.png': 'image/png',
        '.jpg': 'image/jpg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.json': 'application/json',
        '.map': 'application/json',
    }

    def end_headers(self):
        # Add CORS headers for development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def guess_type(self, path):
        # Override the default MIME type guessing
        for ext, mime_type in self.mime_types.items():
            if path.endswith(ext):
                return mime_type
        return super().guess_type(path)

# WebSocket connection handler
async def websocket_handler(websocket):
    try:
        async for message in websocket:
            print(f"Received message: {message}")
            # Echo the message back
            await websocket.send(f"Echo: {message}")
    except websockets.exceptions.ConnectionClosed:
        print("WebSocket connection closed")

# Start WebSocket server
async def start_websocket_server():
    async with websockets.serve(websocket_handler, "localhost", WS_PORT):
        print(f"WebSocket server started at ws://localhost:{WS_PORT}")
        await asyncio.Future()  # Run forever

# Start WebSocket server in a separate thread
def run_websocket_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_websocket_server())

# Start the WebSocket server in a separate thread
ws_thread = threading.Thread(target=run_websocket_server, daemon=True)
ws_thread.start()

# Create an HTTP server with the custom handler
with socketserver.TCPServer(("", PORT), WasmHandler) as httpd:
    print(f"HTTP server running at http://localhost:{PORT}")
    print("MIME types configured for WebAssembly and JavaScript modules")
    print(f"WebSocket server running at ws://localhost:{WS_PORT}")
    httpd.serve_forever() 
