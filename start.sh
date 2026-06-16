#!/bin/bash
cd /home/ubuntu/apps/keikaku-app
/home/ubuntu/apps/keikaku-app/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8312
