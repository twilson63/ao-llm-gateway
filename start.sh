#!/bin/sh
# Render startup script - uses $PORT env var

PORT=${PORT:-8000}
echo "Starting AO LLM Gateway on port $PORT"
exec uvicorn src.main:app --host 0.0.0.0 --port $PORT