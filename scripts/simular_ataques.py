"""
Gera tráfego legítimo e malicioso contra a API local para produzir logs, métricas e alertas
(usado para as evidências de Observabilidade da Sprint 3).
Uso:  python scripts/simular_ataques.py http://localhost:8000 ANALISTA_PASSWORD ADMIN_PASSWORD
"""
import sys
import httpx

base, senha_analista, senha_admin = sys.argv[1], sys.argv[2], sys.argv[3]
c = httpx.Client(base_url=base, timeout=10)
RAPTOR = {"marca": "Ford", "modelo": "Ranger", "versao": "Raptor"}

print("1) Uso legítimo")
tok = c.post("/login", json={"usuario": "analista", "senha": senha_analista}).json()["access_token"]
h = {"Authorization": f"Bearer {tok}"}
print("   busca:", c.post("/buscar", json=RAPTOR, headers=h).status_code)

print("2) Analista tentando acessar rota de admin (escalada de privilégio)")
print("   admin/historico:", c.get("/admin/historico", headers=h).status_code)

print("3) Injeção / XSS na busca")
for p in ["Ford'; DROP TABLE x;--", "<script>alert(1)</script>"]:
    print("   payload:", c.post("/buscar", json={**RAPTOR, "marca": p}, headers=h).status_code)

print("4) Token forjado")
print("   token inválido:", c.get("/veiculos", headers={"Authorization": "Bearer abc.def.ghi"}).status_code)

print("5) Força bruta contra a conta admin")
for i in range(6):
    print(f"   tentativa {i+1}:", c.post("/login", json={"usuario": "admin", "senha": f"chute-{i}-errado"}).status_code)

print("6) Logout (revogação do token)")
print("   logout:", c.post("/logout", headers=h).status_code)
print("   reuso do token:", c.get("/veiculos", headers=h).status_code)
