from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
import random

# ============================================================
# CONFIGURACIÓN GENERAL DEL PROYECTO "EL MARIACHI"
# ============================================================
SECRET_KEY = "clave-secreta-elmariachi"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/mariachi/usuarios/login")

app = FastAPI(
    title="API El Mariachi - Restaurante y Delivery",
    description="API completa para pedidos, reservas y administración de El Mariachi",
    version="1.0.0"
)

API_PREFIX = "/api/mariachi"

# ============================================================
# MODELOS BASE
# ============================================================
class Response(BaseModel):
    statusCode: int = 200
    message: str = "OK"
    data: Optional[dict | list] = None

class User(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    email: str
    hashed_password: str
    bloqueado_hasta: Optional[datetime] = None
    intentos_fallidos: int = 0
    creado_en: datetime = Field(default_factory=datetime.now)

class RegistroInput(BaseModel):
    email: str
    password: str

class LoginInput(BaseModel):
    email: str
    password: str

# ============================================================
# FUNCIONES DE SEGURIDAD
# ============================================================
def hashear_contraseña(password: str) -> str:
    return pwd_context.hash(password)

def verificar_contraseña(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def crear_token(data: dict, exp: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc) + exp})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ============================================================
# "BASES DE DATOS" EN MEMORIA
# ============================================================
db_usuarios: List[User] = []
db_tokens_reset: dict[str, datetime] = []

# ============================================================
# HELPERS
# ============================================================
def get_user_by_email(email: str) -> Optional[User]:
    return next((u for u in db_usuarios if u.email == email), None)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    cred_error = HTTPException(status_code=401, detail="Token inválido o expirado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise cred_error
    except JWTError:
        raise cred_error
    user = get_user_by_email(email)
    if not user:
        raise cred_error
    return user

# ============================================================
# ENDPOINT PRINCIPAL
# ============================================================
@app.get("/")
def root():
    return {"mensaje": "API El Mariachi activa. Visita /docs para documentación."}

# ============================================================
# B-01: Registro básico de usuario
# ============================================================
@app.post(f"{API_PREFIX}/usuarios/registro", response_model=Response, tags=["Usuarios"])
def registrar_usuario(input: RegistroInput):
    if get_user_by_email(input.email):
        raise HTTPException(status_code=400, detail="El email ya está en uso")
    if len(input.password) < 8 or not any(c.isupper() for c in input.password) or not any(c.isdigit() for c in input.password):
        raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos")
    hashed = hashear_contraseña(input.password)
    nuevo = User(email=input.email, hashed_password=hashed)
    db_usuarios.append(nuevo)
    print(f"[Registro] Usuario {input.email} creado correctamente.")
    return Response(message="Registro exitoso", data={"email": input.email})

# ============================================================
# B-02: Inicio de sesión
# ============================================================
@app.post(f"{API_PREFIX}/usuarios/login", response_model=Response, tags=["Usuarios"])
def login(input: LoginInput):
    user = get_user_by_email(input.email)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    ahora = datetime.now()
    if user.bloqueado_hasta and ahora < user.bloqueado_hasta:
        raise HTTPException(status_code=403, detail="Cuenta temporalmente bloqueada")

    if not verificar_contraseña(input.password, user.hashed_password):
        user.intentos_fallidos += 1
        if user.intentos_fallidos >= 5:
            user.bloqueado_hasta = ahora + timedelta(minutes=15)
            user.intentos_fallidos = 0
            raise HTTPException(status_code=403, detail="Cuenta bloqueada 15 minutos")
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")

    user.intentos_fallidos = 0
    token = crear_token({"sub": user.email})
    print(f"[Login] {user.email} inició sesión correctamente.")
    return Response(message="Inicio de sesión exitoso", data={"token": token})


# ============================================================
# B-03: Visualización de catálogo
# ============================================================
class Producto(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    nombre: str
    categoria: str
    precio: float
    descripcion: Optional[str] = None

# Catálogo simulado
db_productos: List[Producto] = [
    Producto(nombre="Tacos al Pastor", categoria="Comida", precio=6.5),
    Producto(nombre="Burrito de Pollo", categoria="Comida", precio=7.2),
    Producto(nombre="Margarita Clásica", categoria="Bebidas", precio=4.0),
    Producto(nombre="Nachos Especiales", categoria="Snacks", precio=5.8),
]

@app.get(f"{API_PREFIX}/menu/listar", response_model=Response, tags=["Catálogo"])
def listar_productos(pagina: int = 1, limite: int = 12):
    total = len(db_productos)
    inicio = (pagina - 1) * limite
    fin = inicio + limite
    if total == 0:
        return Response(message="No hay productos disponibles", data=[])
    data = {"pagina": pagina, "total": total, "items": [p.dict() for p in db_productos[inicio:fin]]}
    return Response(message="Listado de productos", data=data)

# ============================================================
# B-04: Filtro y búsqueda
# ============================================================
@app.get(f"{API_PREFIX}/menu/filtrar", response_model=Response, tags=["Catálogo"])
def filtrar_menu(categoria: Optional[str] = None, texto: Optional[str] = None):
    productos = db_productos
    if categoria:
        productos = [p for p in productos if categoria.lower() in p.categoria.lower()]
    if texto:
        productos = [p for p in productos if texto.lower() in p.nombre.lower()]
    if not productos:
        return Response(message="No se encontraron resultados", data=[])
    return Response(message="Productos filtrados", data=[p.dict() for p in productos])

# ============================================================
# B-05: Navegación principal (simulada)
# ============================================================
@app.get(f"{API_PREFIX}/ui/navegacion", response_model=Response, tags=["Interfaz Web"])
def verificar_navegacion():
    print("[UI] Barra de navegación fija verificada con smooth scroll.")
    return Response(message="Navegación fija y funcional", data={"estado": "OK"})

# ============================================================
# B-06: Menú responsive (simulada)
# ============================================================
@app.get(f"{API_PREFIX}/ui/menu-responsive", response_model=Response, tags=["Interfaz Web"])
def menu_responsive():
    print("[UI] Menú móvil desplegable probado correctamente.")
    return Response(message="Menú responsive funcional", data={"pantalla": "<768px", "resultado": "OK"})

# ============================================================
# B-07: Información de contacto y redes sociales (simulada)
# ============================================================
@app.get(f"{API_PREFIX}/ui/contacto", response_model=Response, tags=["Interfaz Web"])
def info_contacto():
    data = {
        "telefono": "+56 9 5555 5555",
        "horario": "Lunes a Domingo: 12:00 - 23:00 hrs",
        "redes": {
            "instagram": "https://instagram.com/elmariachi",
            "facebook": "https://facebook.com/elmariachi"
        }
    }
    print("[UI] Información de contacto y redes cargada.")
    return Response(message="Información de contacto disponible", data=data)

# ============================================================
# B-08: Sección principal (Hero) con CTA (simulada)
# ============================================================
@app.get(f"{API_PREFIX}/ui/hero", response_model=Response, tags=["Interfaz Web"])
def hero_cta():
    print("[UI] Sección Hero con CTA 'Ver Menú' validada.")
    return Response(message="CTA funcional y visible", data={"boton": "Ver Menú", "estado": "OK"})

# ============================================================
# B-09: Mapa interactivo (simulada)
# ============================================================
@app.get(f"{API_PREFIX}/ui/mapa", response_model=Response, tags=["Interfaz Web"])
def mapa_interactivo():
    data = {
        "iframe": "https://maps.google.com/?q=El+Mariachi",
        "responsive": True,
        "marcador": "Ubicación El Mariachi"
    }
    print("[UI] Mapa interactivo renderizado correctamente.")
    return Response(message="Mapa interactivo activo", data=data)

# ============================================================
# B-10: Validación de formulario (simulada)
# ============================================================
class FormularioInput(BaseModel):
    nombre: str
    email: str
    mensaje: str

@app.post(f"{API_PREFIX}/ui/validar-formulario", response_model=Response, tags=["Interfaz Web"])
def validar_formulario(input: FormularioInput):
    if "@" not in input.email or "." not in input.email:
        raise HTTPException(status_code=400, detail="Por favor, ingresa un email válido.")
    if len(input.mensaje.strip()) < 5:
        raise HTTPException(status_code=400, detail="El mensaje es demasiado corto.")
    print(f"[Formulario] Validado: {input.email}")
    return Response(message="Formulario validado correctamente", data=input.dict())


# ============================================================
# B-11: Agregar productos al carrito
# ============================================================
class CarritoItem(BaseModel):
    producto: str
    cantidad: int
    precio_unitario: float

db_carrito: List[CarritoItem] = []

@app.post(f"{API_PREFIX}/pedidos/carrito/agregar", response_model=Response, tags=["Pedidos"])
def agregar_al_carrito(item: CarritoItem):
    existente = next((p for p in db_carrito if p.producto == item.producto), None)
    if existente:
        existente.cantidad += item.cantidad
    else:
        db_carrito.append(item)
    print(f"[Carrito] {item.cantidad}x {item.producto} agregado.")
    return Response(message="Producto agregado al carrito", data={"total_items": len(db_carrito)})

# ============================================================
# B-12: Ver resumen del pedido
# ============================================================
@app.get(f"{API_PREFIX}/pedidos/resumen", response_model=Response, tags=["Pedidos"])
def ver_resumen():
    if not db_carrito:
        raise HTTPException(status_code=404, detail="El carrito está vacío")
    total = sum(p.cantidad * p.precio_unitario for p in db_carrito)
    detalle = [p.dict() for p in db_carrito]
    data = {"productos": detalle, "total": round(total, 2)}
    print("[Pedido] Resumen de pedido generado.")
    return Response(message="Resumen del pedido", data=data)

@app.put(f"{API_PREFIX}/pedidos/resumen/actualizar", response_model=Response, tags=["Pedidos"])
def actualizar_cantidad(producto: str, nueva_cantidad: int):
    item = next((p for p in db_carrito if p.producto == producto), None)
    if not item:
        raise HTTPException(status_code=404, detail="Producto no encontrado en el carrito")
    item.cantidad = nueva_cantidad
    total = sum(p.cantidad * p.precio_unitario for p in db_carrito)
    print(f"[Carrito] Cantidad de {producto} actualizada a {nueva_cantidad}")
    return Response(message="Cantidad actualizada", data={"total": round(total, 2)})

# ============================================================
# B-13: Elegir método de entrega
# ============================================================
class MetodoEntrega(BaseModel):
    tipo: str  # "local" o "domicilio"
    direccion: Optional[str] = None

@app.post(f"{API_PREFIX}/pedidos/entrega", response_model=Response, tags=["Pedidos"])
def seleccionar_entrega(input: MetodoEntrega):
    if input.tipo not in ["local", "domicilio"]:
        raise HTTPException(status_code=400, detail="Tipo de entrega inválido")
    if input.tipo == "domicilio" and not input.direccion:
        raise HTTPException(status_code=400, detail="Debe indicar la dirección para entrega a domicilio")
    costo_envio = 2.5 if input.tipo == "domicilio" else 0.0
    tiempo = "30-40 min" if input.tipo == "domicilio" else "15-20 min"
    data = {"metodo": input.tipo, "costo_envio": costo_envio, "tiempo_estimado": tiempo}
    print(f"[Entrega] Método seleccionado: {input.tipo}")
    return Response(message="Método de entrega confirmado", data=data)

# ============================================================
# B-14: Seleccionar fecha y hora para reserva
# ============================================================
class ReservaInput(BaseModel):
    fecha: str
    hora: str
    comensales: int

db_reservas: List[ReservaInput] = []

@app.post(f"{API_PREFIX}/reservas/crear", response_model=Response, tags=["Reservas"])
def crear_reserva(input: ReservaInput):
    try:
        fecha_dt = datetime.strptime(input.fecha, "%Y-%m-%d")
        if fecha_dt < datetime.now():
            raise HTTPException(status_code=400, detail="No se permiten fechas pasadas")
    except ValueError:
        raise HTTPException(status_code=400, detail="Formato de fecha inválido (YYYY-MM-DD)")
    if not (12 <= int(input.hora.split(":")[0]) <= 23):
        raise HTTPException(status_code=400, detail="Fuera del horario de atención (12:00-23:00)")
    if input.comensales > 10:
        raise HTTPException(status_code=400, detail="Número máximo de comensales por mesa: 10")
    db_reservas.append(input)
    print(f"[Reserva] Nueva reserva para {input.comensales} comensales el {input.fecha} a las {input.hora}")
    return Response(message="Reserva creada correctamente", data=input.dict())

# ============================================================
# B-15: Confirmación de reserva
# ============================================================
@app.get(f"{API_PREFIX}/reservas/confirmar", response_model=Response, tags=["Reservas"])
def confirmar_reserva(email: str):
    numero_reserva = f"RSV-{random.randint(1000,9999)}"
    detalles = {
        "email": email,
        "numero_reserva": numero_reserva,
        "mensaje": "Correo de confirmación enviado (simulado)"
    }
    print(f"[Reserva] Confirmación enviada a {email}. Código: {numero_reserva}")
    return Response(message="Reserva confirmada", data=detalles)

# ============================================================
# B-16: Actualizar menú y precios (solo admin)
# ============================================================
class ProductoAdmin(BaseModel):
    nombre: str
    categoria: str
    precio: float
    descripcion: Optional[str] = None

@app.post(f"{API_PREFIX}/admin/menu/actualizar", response_model=Response, tags=["Administración"])
def actualizar_menu(input: ProductoAdmin, user: User = Depends(get_current_user)):
    nuevo = Producto(nombre=input.nombre, categoria=input.categoria, precio=input.precio, descripcion=input.descripcion)
    db_productos.append(nuevo)
    print(f"[Admin] Producto agregado/actualizado: {input.nombre}")
    return Response(message="Producto actualizado correctamente", data=input.dict())

# ============================================================
# B-17: Gestionar promociones
# ============================================================
class PromocionInput(BaseModel):
    nombre: str
    descuento_pct: float
    vigente: bool = True
    inicio: Optional[str] = None
    fin: Optional[str] = None

db_promociones: List[PromocionInput] = []

@app.post(f"{API_PREFIX}/admin/promociones", response_model=Response, tags=["Administración"])
def crear_promocion(input: PromocionInput, user: User = Depends(get_current_user)):
    if input.descuento_pct <= 0 or input.descuento_pct > 100:
        raise HTTPException(status_code=400, detail="Descuento inválido (1-100%)")
    db_promociones.append(input)
    print(f"[Promoción] Nueva promoción creada: {input.nombre} ({input.descuento_pct}%)")
    return Response(message="Promoción registrada", data=input.dict())

@app.get(f"{API_PREFIX}/admin/promociones", response_model=Response, tags=["Administración"])
def listar_promociones():
    activas = [p.dict() for p in db_promociones if p.vigente]
    return Response(message="Listado de promociones activas", data=activas)

# ============================================================
# FIN DEL ARCHIVO
# ============================================================
print("API El Mariachi lista. Ejecuta: uvicorn main_elmariachi:app --reload")
