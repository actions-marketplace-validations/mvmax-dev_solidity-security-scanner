FROM python:3.11-slim

# Install solc and system dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN pip install --no-cache-dir web3 slither-analyzer solc-select

# Install common solc versions for Slither
RUN solc-select install 0.8.20 && \
    solc-select install 0.8.24 && \
    solc-select use 0.8.24

# Copy the scanner code
COPY . /app
WORKDIR /app

# The entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
