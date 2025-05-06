# setup_venv.sh
#!/bin/bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install faker
pip install fastapi uvicorn python-dotenv
uvicorn dynamic_response:app --host 0.0.0.0 --port 8080
