.PHONY: help install test test-backend test-frontend lint build run-backend run-frontend

help:
	@echo "ZeroTrace Development Commands:"
	@echo "  make install        Install backend and frontend dependencies"
	@echo "  make test           Run all backend (pytest) and frontend (vitest) tests"
	@echo "  make test-backend   Run backend pytest suite"
	@echo "  make test-frontend  Run frontend vitest suite"
	@echo "  make lint           Run frontend linter (oxlint)"
	@echo "  make build          Build production frontend bundle"
	@echo "  make run-backend    Launch FastAPI backend server on 127.0.0.1:8000"
	@echo "  make run-frontend   Launch Vite dev server on 127.0.0.1:5173"

install:
	pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && npm install

test: test-backend test-frontend

test-backend:
	pytest tests/ -v -m "not slow"

test-frontend:
	cd frontend && npm test -- --run

lint:
	cd frontend && npm run lint

build:
	cd frontend && npm run build

run-backend:
	python run_backend.py

run-frontend:
	cd frontend && npm run dev -- --host 127.0.0.1 --port 5173
