import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pwdlib import PasswordHash
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import (
    create_engine,
    String,
    Integer,
    Boolean,
    Text,
    ForeignKey,
    DateTime,
    or_
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
    Session
)

# ============================================================
# CONFIGURACIÓN
# ============================================================

load_dotenv()

IS_VERCEL = os.getenv("VERCEL") == "1"

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./recetario.db")
SECRET = os.getenv(
    "JWT_SECRET_KEY",
    "local-development-secret-change-me"
)

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    "admin@recetario.local"
).strip().lower()

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    "ChangeMe123!"
)

JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "720")
)

ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:4200"
    ).split(",")
    if origin.strip()
]

if IS_VERCEL:
    if not os.getenv("DATABASE_URL"):
        raise RuntimeError("Configura DATABASE_URL en Vercel.")

    if SECRET == "local-development-secret-change-me":
        raise RuntimeError("Configura JWT_SECRET_KEY en Vercel.")

    if ADMIN_PASSWORD == "ChangeMe123!":
        raise RuntimeError("Configura ADMIN_PASSWORD en Vercel.")

    if len(SECRET) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY debe tener al menos 32 caracteres."
        )

    if not ADMIN_EMAIL:
        raise RuntimeError("Configura ADMIN_EMAIL en Vercel.")

    if not ADMIN_PASSWORD:
        raise RuntimeError("Configura ADMIN_PASSWORD en Vercel.")


# ============================================================
# CONEXIÓN POSTGRESQL / SQLITE
# ============================================================

def normalize_database_url(url: str) -> str:
    """
    Convierte las URLs PostgreSQL de Neon al controlador
    Psycopg 3 utilizado por SQLAlchemy.
    """

    url = url.strip()

    if not url:
        raise RuntimeError("DATABASE_URL está vacío.")

    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]

    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]

    return url


DB_URL = normalize_database_url(DB_URL)

if DB_URL.startswith("sqlite"):
    engine = create_engine(
        DB_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True
    )
else:
    from sqlalchemy.pool import NullPool

    engine = create_engine(
        DB_URL,
        pool_pre_ping=True,
        poolclass=NullPool
    )


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


# ============================================================
# SEGURIDAD
# ============================================================

hasher = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)


# ============================================================
# MODELOS
# ============================================================

class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    name: Mapped[str] = mapped_column(String(120))

    email: Mapped[str] = mapped_column(
        String(180),
        unique=True,
        index=True
    )

    password_hash: Mapped[str] = mapped_column(String(500))

    role: Mapped[str] = mapped_column(
        String(20),
        default="user"
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    recipes: Mapped[list["Recipe"]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan"
    )


class Recipe(Base):
    __tablename__ = "recipes"

    id: Mapped[int] = mapped_column(primary_key=True)

    title: Mapped[str] = mapped_column(String(180))

    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    ingredients: Mapped[str] = mapped_column(
        Text,
        default=""
    )

    instructions: Mapped[str] = mapped_column(
        Text,
        default=""
    )

    category: Mapped[str] = mapped_column(
        String(80),
        default="General"
    )

    prep_time: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )

    servings: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True
    )

    image_url: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True
    )

    created_by: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    owner: Mapped[User] = relationship(
        back_populates="recipes"
    )


# ============================================================
# ESQUEMAS
# ============================================================

class Login(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str
    password: str = Field(min_length=8, max_length=128)
    role: str = "user"


class UserPatch(BaseModel):
    name: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=120
    )

    email: Optional[str] = None

    password: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=128
    )

    role: Optional[str] = None
    active: Optional[bool] = None


class RecipeIn(BaseModel):
    title: str = Field(min_length=2, max_length=180)
    description: Optional[str] = None
    ingredients: str = ""
    instructions: str = ""
    category: str = "General"
    prep_time: Optional[int] = None
    servings: Optional[int] = None
    image_url: Optional[str] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: str
    role: str
    active: bool
    created_at: datetime


# ============================================================
# SESIONES DE BASE DE DATOS
# ============================================================

def db_session():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# AUTENTICACIÓN
# ============================================================

def auth(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(db_session)
):
    if not creds:
        raise HTTPException(
            status_code=401,
            detail="Inicia sesión para continuar."
        )

    try:
        payload = jwt.decode(
            creds.credentials,
            SECRET,
            algorithms=["HS256"]
        )

        uid = int(payload["sub"])

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Sesión inválida o vencida."
        )

    user = db.get(User, uid)

    if not user or not user.active:
        raise HTTPException(
            status_code=401,
            detail="Cuenta inexistente o desactivada."
        )

    return user


def admin(user: User = Depends(auth)):
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Acción exclusiva del administrador."
        )

    return user


def token(user):
    now = datetime.now(timezone.utc)

    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "exp": now + timedelta(
                minutes=JWT_EXPIRE_MINUTES
            )
        },
        SECRET,
        algorithm="HS256"
    )


# ============================================================
# CONVERSIÓN DE RECETAS
# ============================================================

def recipe_json(recipe):
    return {
        "id": recipe.id,
        "title": recipe.title,
        "description": recipe.description,
        "ingredients": recipe.ingredients,
        "instructions": recipe.instructions,
        "category": recipe.category,
        "prep_time": recipe.prep_time,
        "servings": recipe.servings,
        "image_url": recipe.image_url,
        "created_by": recipe.created_by,
        "creator_name": recipe.owner.name,
        "created_at": recipe.created_at
    }


# ============================================================
# APLICACIÓN FASTAPI
# IMPORTANTE: DEBE ESTAR ANTES DE LAS RUTAS Y STARTUP
# ============================================================

app = FastAPI(
    title="Mi Recetario API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# INICIALIZACIÓN DE LA BASE DE DATOS
# ============================================================

def initialize_database():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        existing = db.query(User).filter(
            User.email == ADMIN_EMAIL
        ).first()

        if not existing:
            administrator = User(
                name="Administrador",
                email=ADMIN_EMAIL,
                password_hash=hasher.hash(ADMIN_PASSWORD),
                role="admin",
                active=True
            )

            db.add(administrator)

            try:
                db.commit()
            except IntegrityError:
                db.rollback()


@app.on_event("startup")
def startup():
    initialize_database()


# ============================================================
# SALUD DEL SERVIDOR
# ============================================================

@app.get("/")
def root():
    return {
        "message": "Mi Recetario API está funcionando.",
        "docs": "/docs"
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ============================================================
# AUTENTICACIÓN Y USUARIOS
# ============================================================

@app.post("/api/auth/login")
def login(
    data: Login,
    db: Session = Depends(db_session)
):
    user = db.query(User).filter(
        User.email == data.email.strip().lower()
    ).first()

    if (
        not user
        or not user.active
        or not hasher.verify(data.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Correo o contraseña incorrectos."
        )

    return {
        "access_token": token(user),
        "token_type": "bearer",
        "user": UserOut.model_validate(user)
    }


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(auth)):
    return user


@app.get("/api/users", response_model=list[UserOut])
def users(
    _: User = Depends(admin),
    db: Session = Depends(db_session)
):
    return db.query(User).order_by(
        User.id.desc()
    ).all()


@app.post(
    "/api/users",
    response_model=UserOut,
    status_code=201
)
def add_user(
    data: UserCreate,
    _: User = Depends(admin),
    db: Session = Depends(db_session)
):
    email = data.email.strip().lower()

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=409,
            detail="Ese correo ya existe."
        )

    if data.role not in ("user", "admin"):
        raise HTTPException(
            status_code=422,
            detail="Rol inválido."
        )

    user = User(
        name=data.name,
        email=email,
        password_hash=hasher.hash(data.password),
        role=data.role
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@app.patch("/api/users/{uid}", response_model=UserOut)
def edit_user(
    uid: int,
    data: UserPatch,
    a: User = Depends(admin),
    db: Session = Depends(db_session)
):
    user = db.get(User, uid)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado."
        )

    changes = data.model_dump(exclude_unset=True)

    password = changes.pop("password", None)

    if password:
        user.password_hash = hasher.hash(password)

    if changes.get("email"):
        email = str(changes["email"]).strip().lower()

        duplicate = db.query(User).filter(
            User.email == email,
            User.id != uid
        ).first()

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="Correo ya registrado."
            )

        changes["email"] = email

    if changes.get("role") not in (None, "user", "admin"):
        raise HTTPException(
            status_code=422,
            detail="Rol inválido."
        )

    if uid == a.id and changes.get("active") is False:
        raise HTTPException(
            status_code=400,
            detail="No puedes desactivar tu propia cuenta."
        )

    for key, value in changes.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)

    return user


@app.delete("/api/users/{uid}")
def remove_user(
    uid: int,
    a: User = Depends(admin),
    db: Session = Depends(db_session)
):
    user = db.get(User, uid)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado."
        )

    if uid == a.id:
        raise HTTPException(
            status_code=400,
            detail="No puedes eliminar tu propia cuenta."
        )

    db.delete(user)
    db.commit()

    return {"message": "Cuenta eliminada."}


# ============================================================
# RECETAS
# ============================================================

@app.get("/api/recipes")
def recipes(
    q: Optional[str] = None,
    category: Optional[str] = None,
    _: User = Depends(auth),
    db: Session = Depends(db_session)
):
    query = db.query(Recipe)

    if q:
        query = query.filter(
            or_(
                Recipe.title.ilike(f"%{q}%"),
                Recipe.ingredients.ilike(f"%{q}%"),
                Recipe.description.ilike(f"%{q}%")
            )
        )

    if category and category != "Todas":
        query = query.filter(
            Recipe.category == category
        )

    results = query.order_by(
        Recipe.id.desc()
    ).all()

    return [
        recipe_json(recipe)
        for recipe in results
    ]


@app.post("/api/recipes", status_code=201)
def add_recipe(
    data: RecipeIn,
    user: User = Depends(auth),
    db: Session = Depends(db_session)
):
    recipe = Recipe(
        **data.model_dump(),
        created_by=user.id
    )

    db.add(recipe)
    db.commit()
    db.refresh(recipe)

    return recipe_json(recipe)


@app.put("/api/recipes/{rid}")
def edit_recipe(
    rid: int,
    data: RecipeIn,
    user: User = Depends(auth),
    db: Session = Depends(db_session)
):
    recipe = db.get(Recipe, rid)

    if not recipe:
        raise HTTPException(
            status_code=404,
            detail="Receta no encontrada."
        )

    if user.role != "admin" and recipe.created_by != user.id:
        raise HTTPException(
            status_code=403,
            detail="Solo puedes editar tus propias recetas."
        )

    for key, value in data.model_dump().items():
        setattr(recipe, key, value)

    db.commit()
    db.refresh(recipe)

    return recipe_json(recipe)


@app.delete("/api/recipes/{rid}")
def remove_recipe(
    rid: int,
    user: User = Depends(auth),
    db: Session = Depends(db_session)
):
    recipe = db.get(Recipe, rid)

    if not recipe:
        raise HTTPException(
            status_code=404,
            detail="Receta no encontrada."
        )

    if user.role != "admin" and recipe.created_by != user.id:
        raise HTTPException(
            status_code=403,
            detail="Solo puedes eliminar tus propias recetas."
        )

    db.delete(recipe)
    db.commit()

    return {"message": "Receta eliminada."}
