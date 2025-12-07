#!/bin/bash

# Function to kill background processes on exit
cleanup() {
    echo "Stopping services..."
    kill $(jobs -p) 2>/dev/null
    exit
}

# Trap SIGINT and SIGTERM
trap cleanup SIGINT SIGTERM

echo "Starting Backend (FastAPI)..."
uv run uvicorn backend.main:app --port 8000 --reload &
BACKEND_PID=$!

echo "Waiting for backend to initialize..."
sleep 2

echo "Starting Frontend (Streamlit)..."
uv run streamlit run frontend/app.py &
FRONTEND_PID=$!

echo "App is running!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:8501"
echo "Press Ctrl+C to stop."

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID
