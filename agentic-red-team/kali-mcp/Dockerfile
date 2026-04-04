FROM kalilinux/kali-rolling

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install Kali headless toolset + Python + curl for uv installer
RUN apt-get update && apt-get -y install \
    kali-linux-headless \
    python3 \
    python3-venv \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Decompress rockyou wordlist if not already done
RUN gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock ./
COPY app/ ./

# Install Python dependencies with uv
RUN uv sync --frozen

EXPOSE 3000

CMD ["uv", "run", "main.py", "--ip", "0.0.0.0", "--port", "3000"]
