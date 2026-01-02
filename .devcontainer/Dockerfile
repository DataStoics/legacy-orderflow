FROM mcr.microsoft.com/devcontainers/python:3.11

# Set working directory
WORKDIR /workspace

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5001

# Default command (can be overridden)
CMD ["python", "app.py"]
