#!/bin/bash
set -e
cd "$(dirname "$0")/backend"

if [ ! -d "venv" ]; then
  echo "Creating virtualenv..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt
pip install -q python-dotenv

echo ""
echo "================================================"
echo "  Ecosystem Early Warning Agent"
echo "  Local:  http://localhost:8000"
echo "================================================"

# Optional: expose publicly for judges via ngrok
# Install ngrok: brew install ngrok
# Authenticate:  ngrok config add-authtoken <your-token>
# Then run in a separate terminal:
#   ngrok http 8000
# Copy the https://*.ngrok-free.app URL for judges

echo ""
# Kill any existing server on port 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null; sleep 1

# Load .env (optional NVD_API_KEY etc.) before uvicorn forks
set -a
[ -f .env ] && source .env
set +a

# Use gunicorn with uvicorn workers in production-like mode
# Workers = 2 × CPU cores + 1 (handles concurrent scans without blocking)
WORKERS=${WEB_CONCURRENCY:-$(python3 -c "import os; print(2 * os.cpu_count() + 1)")}
exec gunicorn main:app \
  --env PYTHONWARNINGS=ignore \
  --workers "$WORKERS" \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --graceful-timeout 30 \
  --access-logfile -
