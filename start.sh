#!/bin/sh
# Render startup script - uses $PORT env var

# Create data directory for LMDB and SQLite
mkdir -p /app/data

# Set default port
PORT=${PORT:-8000}

echo "Starting AO LLM Gateway on port $PORT"
echo "Initializing database and LMDB store..."

# Run Alembic migrations
cd /app
python -m alembic upgrade head

# Start the application
exec uvicorn src.main:app --host 0.0.0.0 --port $PORT