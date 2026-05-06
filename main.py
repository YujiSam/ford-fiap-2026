from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime, timedelta
import re
import logging
import jwt
from cryptography.fernet import Fernet

# ==================== APP ====================
app = FastAPI(title="Ford Inteligência Competitiva")

# ==================== CORS ====================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== CONFIGURAÇÕES ====================
SECRET_KEY = "minha-chave-secreta-forte-2026"
ALGORITHM = "HS256"

# Chave Fernet (em produção, guarde em variável de ambiente)
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

# ==================== LOGS ====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ford-api")

# ==================== FUNÇÕES AUXILIARES ====================
def criptografar(dado: str) -> str:
    if not dado:
        return ""
    return cipher.encrypt(dado.encode()).decode()

def descriptografar(dado_cripto: str) -> str:
    if not dado_cripto:
        return ""
    return cipher.decrypt(dado_cripto.encode()).decode()

def anonimizar_email(email: str) -> str:
    if not email or "@" not in email:
        return "anonimo"
    local, dominio = email.split("@")
    if len(local) <= 1:
        return f"*@{dominio}"
    return f"{local[0]}****@{dominio}"

# ==================== MODELOS ====================
class BuscaRequest(BaseModel):
    marca: str = Field(..., min_length=1, max_length=50)
    modelo: str = Field(..., min_length=1, max_length=50)
    versao: str = Field(..., min_length=1, max_length=50)
    atributos: Optional[List[str]] = None

    @validator("marca", "modelo", "versao")
    def sanitizar(cls, v):
        # Remove caracteres perigosos
        v = re.sub(r'[;\"\'`]', '', v)
        return v.strip()[:50]

class LoginRequest(BaseModel):
    usuario: str
    senha: str

# ==================== DADOS ====================
DADOS_RANGER_RAPTOR = {
    "motor": "V6 3.0L Nano bi turbo",
    "potencia": "397cv @ 5650 RPM",
    "torque_max": "583 Nm @ 3500 RPM",
    "transmissao": "AT de 10 velocidades e paddle shifters",
    "tracao": "4WD",
    "amortecedores": "Live Valve FOX Racing 2.5\"",
    "0-100_kmh": "5.8s",
    "farois": "Matrix LED",
    "rodas_pneus": "17\" com 285/70 R17 AT",
    "preco": "R$ 499.000"
}

# Usuários com email (para anonimização)
USUARIOS = {
    "analista": {"senha": "123456", "role": "analista", "email": "analista@ford.com"},
    "admin":   {"senha": "admin123", "role": "admin",   "email": "admin@ford.com"}
}

historico_buscas = []  # para armazenar buscas criptografadas

# ==================== JWT ====================
def criar_token(usuario: str, role: str):
    payload = {
        "sub": usuario,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token(creds: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

def requer_role(role_necessaria: str):
    def dependencia(payload=Depends(verificar_token)):
        if payload.get("role") != role_necessaria:
            raise HTTPException(status_code=403, detail="Acesso negado")
        return payload
    return dependencia

# ==================== ROTAS ====================
@app.get("/")
def root():
    return {"mensagem": "API Ford", "status": "online", "versao": "3.0-com-criptografia"}

@app.post("/login")
def login(request: LoginRequest):
    usuario = USUARIOS.get(request.usuario)
    if not usuario or usuario["senha"] != request.senha:
        logger.warning(f"Falha login: {anonimizar_email(request.usuario)}")
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = criar_token(request.usuario, usuario["role"])
    logger.info(f"Login OK: {anonimizar_email(usuario['email'])} - Role: {usuario['role']}")
    return {"access_token": token, "token_type": "bearer", "role": usuario["role"]}

@app.post("/buscar")
def buscar(request: BuscaRequest, payload=Depends(verificar_token)):
    usuario_email = USUARIOS.get(payload["sub"], {}).get("email", payload["sub"])
    logger.info(f"Busca: {request.marca} {request.modelo} {request.versao} - Usuário: {anonimizar_email(usuario_email)}")

    # Salva no histórico criptografado
    historico_buscas.append({
        "usuario": criptografar(payload["sub"]),
        "marca": criptografar(request.marca),
        "modelo": criptografar(request.modelo),
        "versao": criptografar(request.versao),
        "timestamp": criptografar(datetime.utcnow().isoformat())
    })

    # Validação obrigatória: Ford Ranger Raptor
    if request.marca.lower() == "ford" and request.modelo.lower() == "ranger" and request.versao.lower() == "raptor":
        resultado = DADOS_RANGER_RAPTOR.copy()
        if request.atributos:
            return {attr: resultado.get(attr, "não disponível") for attr in request.atributos}
        return resultado

    raise HTTPException(status_code=404, detail="Veículo não encontrado")

@app.get("/veiculos")
def listar_veiculos(payload=Depends(verificar_token)):
    return {"veiculos": ["Ford Ranger Raptor"]}

@app.get("/admin/historico")
def admin_historico(payload=Depends(requer_role("admin"))):
    """Apenas admin pode ver o histórico descriptografado"""
    historico_clear = []
    for item in historico_buscas:
        try:
            historico_clear.append({
                "usuario": descriptografar(item["usuario"]),
                "marca": descriptografar(item["marca"]),
                "modelo": descriptografar(item["modelo"]),
                "versao": descriptografar(item["versao"]),
                "timestamp": descriptografar(item["timestamp"])
            })
        except:
            continue
    return {"total_buscas": len(historico_clear), "historico": historico_clear}

@app.get("/admin/teste-criptografia")
def teste_criptografia(dado: str, payload=Depends(requer_role("admin"))):
    cripto = criptografar(dado)
    decripto = descriptografar(cripto)
    return {
        "original": dado,
        "criptografado": cripto,
        "descriptografado": decripto,
        "funciona": dado == decripto
    }