# OrderFlow Inc. Order Management System

Internal order management system. Version 2.3.1.

## Quick Start (Recommended)

### GitHub Codespaces
Click the green "Code" button → "Codespaces" → "Create codespace on main"

The server starts automatically on port 5001.

### Local with Docker
```bash
docker-compose up
```
Server runs at http://localhost:5001

### Local without Docker
```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activate (macOS/Linux)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python app.py
```

Server runs on port 5001.

## Testing the API

Use the included `test-api.http` file with the REST Client VS Code extension.

## API

See code for endpoints.

## Notes

- Previous maintainer left June 2024
- Don't change anything unless absolutely necessary
- If something breaks, restart the server
