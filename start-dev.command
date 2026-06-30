#!/bin/bash
cd "$(dirname "$0")"
echo "Starting Ticket Terminator dev server on http://localhost:8888"
echo "Open that URL in Chrome once you see 'Serving on port 8888'"
echo ""
python3 dev-server.py
