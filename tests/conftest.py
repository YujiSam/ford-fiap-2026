"""Ambiente de teste: segredos sintéticos (nunca use estes valores fora dos testes)."""
import os

from cryptography.fernet import Fernet

os.environ.update({
    "ENV": "test",
    "JWT_SECRET": "teste-jwt-secret-com-mais-de-32-caracteres-0123456789",
    "FERNET_KEYS": Fernet.generate_key().decode(),
    "ANALISTA_PASSWORD": "Analista#Teste-2026",
    "ADMIN_PASSWORD": "Admin#Teste-2026-Forte",
    "METRICS_TOKEN": "metrics-token-de-teste-1234567890",
    "CORS_ORIGINS": "http://localhost:3000",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

ANALISTA = ("analista", os.environ["ANALISTA_PASSWORD"])
ADMIN = ("admin", os.environ["ADMIN_PASSWORD"])


@pytest.fixture(autouse=True)
def estado_limpo():
    """Cada teste começa sem rate limit, bloqueios, revogações ou histórico."""
    main.limiter.reset()
    main.FALHAS.clear()
    main.REVOGADOS.clear()
    main.HISTORICO.clear()
    yield


@pytest.fixture()
def client():
    return TestClient(main.app, raise_server_exceptions=False)


def _login(client, cred):
    r = client.post("/login", json={"usuario": cred[0], "senha": cred[1]})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def token_analista(client):
    return _login(client, ANALISTA)


@pytest.fixture()
def token_admin(client):
    return _login(client, ADMIN)


def auth(token):
    return {"Authorization": f"Bearer {token}"}
