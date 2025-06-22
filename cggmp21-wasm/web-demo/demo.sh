#!/bin/bash

# CGGMP21 Web Demo Setup and Launch Script

set -e

echo "🔐 CGGMP21 Hierarchical Threshold Secret Sharing Demo"
echo "===================================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ and try again."
    echo "   Download from: https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2)
REQUIRED_VERSION="16.0.0"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$NODE_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Node.js version $NODE_VERSION is too old. Required: $REQUIRED_VERSION+"
    exit 1
fi

echo "✅ Node.js version: $NODE_VERSION"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Please run this script from the web-demo directory"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
else
    echo "✅ Dependencies already installed"
fi

# Check if WASM files exist
if [ ! -f "../pkg/cggmp21_wasm.js" ]; then
    echo "❌ WASM files not found. Please build the WASM module first:"
    echo "   cd .. && ./build.sh"
    exit 1
fi

echo "✅ WASM module found"

# Function to open browser tabs (platform-specific)
open_browser() {
    local url="http://localhost:8080"
    
    if command -v open &> /dev/null; then
        # macOS
        echo "🌐 Opening browser tabs (macOS)..."
        open "$url"
        sleep 1
        open "$url"
        sleep 1
        open "$url"
    elif command -v xdg-open &> /dev/null; then
        # Linux
        echo "🌐 Opening browser tabs (Linux)..."
        xdg-open "$url" &
        sleep 1
        xdg-open "$url" &
        sleep 1
        xdg-open "$url" &
    elif command -v start &> /dev/null; then
        # Windows
        echo "🌐 Opening browser tabs (Windows)..."
        start "$url"
        sleep 1
        start "$url"
        sleep 1
        start "$url"
    else
        echo "🌐 Please manually open 3 browser tabs to: $url"
    fi
}

# Parse command line arguments
case "${1:-start}" in
    "start")
        echo "🚀 Starting CGGMP21 Demo Server..."
        echo "   Server will be available at: http://localhost:8080"
        echo "   Press Ctrl+C to stop the server"
        echo ""
        
        # Start server in background
        npm start &
        SERVER_PID=$!
        
        # Wait for server to start
        echo "⏳ Waiting for server to start..."
        # sleep 3
        
        # Open browser tabs
        # open_browser
        
        echo ""
        echo "🎉 Demo Setup Complete!"
        echo ""
        echo "Instructions:"
        echo "1. You should now have 3 browser tabs open"
        echo "2. In each tab, set a different Party ID (0, 1, 2)"
        echo "3. Click 'Connect to Server' in each tab"
        echo "4. Click 'Start Full Protocol' in any tab"
        echo "5. Watch the threshold signing demonstration!"
        echo ""
        echo "Press Ctrl+C to stop the demo server..."
        
        # Wait for the server process
        wait $SERVER_PID
        ;;
        
    "debug")
        echo "🐛 Starting server in debug mode..."
        npm run debug
        ;;
        
    "install")
        echo "📦 Installing dependencies..."
        npm install
        echo "✅ Setup complete! Run './demo.sh start' to launch the demo"
        ;;
        
    "help"|"-h"|"--help")
        echo "Usage: ./demo.sh [command]"
        echo ""
        echo "Commands:"
        echo "  start    Start the demo server and open browser tabs (default)"
        echo "  debug    Start server with debug logging"
        echo "  install  Install dependencies only"
        echo "  help     Show this help message"
        echo ""
        echo "Demo Instructions:"
        echo "1. Run './demo.sh start' to launch everything"
        echo "2. Configure Party IDs (0, 1, 2) in each browser tab"
        echo "3. Connect all parties and start the protocol"
        echo "4. Watch the real-time CGGMP21 protocol execution!"
        ;;
        
    *)
        echo "❌ Unknown command: $1"
        echo "Run './demo.sh help' for usage information"
        exit 1
        ;;
esac 
