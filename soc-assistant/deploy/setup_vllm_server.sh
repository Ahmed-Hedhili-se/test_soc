#!/usr/bin/env bash
# setup_vllm_server.sh
#
# Sets up and starts a vLLM server serving Foundation-Sec-8B-Instruct (AWQ).
# Idempotent and parameterized for a 24GB GPU environment.
#
# NOTE: the currently deployed setup runs Ollama (gpt-oss:20b) instead --
# see config/models.yaml -- because running vLLM per-role hit GPU OOM in
# practice. This script is kept as the alternative self-hosting path for
# when dedicated per-role checkpoints are viable again.

set -euo pipefail

# --- Configuration ---
PORT="${PORT:-8000}"
MODEL_REPO="${MODEL_REPO:-fdtn-ai/Foundation-Sec-8B}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-8192}"
MAX_NUM_SEQS="${MAX_NUM_SEQS:-8}"
VENV_DIR="${VENV_DIR:-/opt/vllm-env}"

# Ensure HF_TOKEN is available if needed for gated repos
# export HF_TOKEN="your_token_here" (do not hardcode)

# --- Functions ---

setup_venv() {
    echo "[*] Setting up virtual environment at $VENV_DIR..."
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
        echo "[+] Virtual environment created."
    else
        echo "[+] Virtual environment already exists."
    fi
}

install_vllm() {
    echo "[*] Installing vLLM..."
    # Activate venv for this subshell
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    pip install vllm --break-system-packages
    echo "[+] vLLM installed."
}

start_server() {
    echo "[*] Starting vLLM server..."
    source "$VENV_DIR/bin/activate"

    # Check if a process is already bound to the port
    if lsof -i ":$PORT" > /dev/null 2>&1; then
        echo "[-] Error: Port $PORT is already in use. Please stop the existing server."
        exit 1
    fi

    # Start the server using nohup to detach it from the SSH session
    nohup python -m vllm.entrypoints.openai.api_server \
        --model "$MODEL_REPO" \
        --quantization fp8 \
        --dtype float16 \
        --gpu-memory-utilization 0.90 \
        --max-model-len "$MAX_MODEL_LEN" \
        --max-num-seqs "$MAX_NUM_SEQS" \
        --port "$PORT" \
        --served-model-name foundation-sec-8b-instruct \
        > vllm_server.log 2>&1 &

    echo "[+] vLLM server started in background (PID $!). Logs in vllm_server.log."
}

health_check() {
    echo "[*] Waiting for server to initialize (this can take several minutes to load weights)..."
    # Basic polling until the endpoint responds
    max_retries=60
    count=0
    while [ $count -lt $max_retries ]; do
        if curl -s "http://localhost:$PORT/v1/models" > /dev/null; then
            echo "[+] Health check passed! Server is up and running."
            echo "    Endpoint: http://localhost:$PORT/v1/models"
            curl -s "http://localhost:$PORT/v1/models" | grep -i foundation-sec-8b-instruct || true
            exit 0
        fi
        sleep 5
        count=$((count+1))
    done
    echo "[-] Health check timed out after 5 minutes. Check vllm_server.log for details."
    exit 1
}

# --- Main execution ---
setup_venv
install_vllm
start_server
health_check
