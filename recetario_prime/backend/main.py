import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy import create_engine, String, Integer, Boolean, Text, ForeignKey, DateTime, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

load_dotenv()
DB_URL=os.getenv("DATABASE_URL","sqlite:///./recetario.db")
SECRET=os.getenv("JWT_SECRET_KEY","replace-this-secret")
ADMIN_EMAIL=os.getenv("ADMIN_EMAIL","admin@recetario.local").lower()
ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD","ChangeMe123!")
ORIGINS=[x.strip() for x in os.getenv("CORS_ORIGINS","http://localhost:4200").split(",")]
engine=create_engine(DB_URL,connect_args={"check_same_thread":False} if DB_URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)
hasher=PasswordHash.recommended()
bearer=HTTPBearer(auto_error=False)

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(primary_key=True)
    name:Mapped[str]=mapped_column(String(120))
    email:Mapped[str]=mapped_column(String(180),unique=True,index=True)
    password_hash:Mapped[str]=mapped_column(String(500))
    role:Mapped[str]=mapped_column(String(20),default="user")
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    recipes:Mapped[list["Recipe"]]=relationship(back_populates="owner",cascade="all, delete-orphan")
class Recipe(Base):
    __tablename__="recipes"
    id:Mapped[int]=mapped_column(primary_key=True)
    title:Mapped[str]=mapped_column(String(180))
    description:Mapped[Optional[str]]=mapped_column(Text,nullable=True)
    ingredients:Mapped[str]=mapped_column(Text,default="")
    instructions:Mapped[str]=mapped_column(Text,default="")
    category:Mapped[str]=mapped_column(String(80),default="General")
    prep_time:Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    servings:Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    image_url:Mapped[Optional[str]]=mapped_column(String(1000),nullable=True)
    created_by:Mapped[int]=mapped_column(ForeignKey("users.id"))
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    owner:Mapped[User]=relationship(back_populates="recipes")

class Login(BaseModel):
    email: str
    password:str
class UserCreate(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    email: str
    password:str=Field(min_length=8,max_length=128)
    role:str="user"
class UserPatch(BaseModel):
    name:Optional[str]=None
    email:Optional[str]=None
    password:Optional[str]=None
    role:Optional[str]=None
    active:Optional[bool]=None
class RecipeIn(BaseModel):
    title:str=Field(min_length=2,max_length=180)
    description:Optional[str]=None
    ingredients:str=""
    instructions:str=""
    category:str="General"
    prep_time:Optional[int]=None
    servings:Optional[int]=None
    image_url:Optional[str]=None
class UserOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:int; name:str; email:str; role:str; active:bool; created_at:datetime

def db_session():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def auth(creds:Optional[HTTPAuthorizationCredentials]=Depends(bearer),db:Session=Depends(db_session)):
    if not creds: raise HTTPException(401,"Inicia sesión para continuar.")
    try: uid=int(jwt.decode(creds.credentials,SECRET,algorithms=["HS256"])["sub"])
    except Exception: raise HTTPException(401,"Sesión inválida o vencida.")
    u=db.get(User,uid)
    if not u or not u.active: raise HTTPException(401,"Cuenta inexistente o desactivada.")
    return u
def admin(u:User=Depends(auth)):
    if u.role!="admin": raise HTTPException(403,"Acción exclusiva del administrador.")
    return u
def token(u):
    now=datetime.now(timezone.utc)
    return jwt.encode({"sub":str(u.id),"iat":now,"exp":now+timedelta(minutes=int(os.getenv("JWT_EXPIRE_MINUTES","720")))},SECRET,algorithm="HS256")
def recipe_json(r):
    return {"id":r.id,"title":r.title,"description":r.description,"ingredients":r.ingredients,"instructions":r.instructions,"category":r.category,"prep_time":r.prep_time,"servings":r.servings,"image_url":r.image_url,"created_by":r.created_by,"creator_name":r.owner.name,"created_at":r.created_at}

app=FastAPI(title="Mi Recetario API")
app.add_middleware(CORSMiddleware,allow_origins=ORIGINS,allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not db.query(User).filter(User.email==ADMIN_EMAIL).first():
            db.add(User(name="Administrador",email=ADMIN_EMAIL,password_hash=hasher.hash(ADMIN_PASSWORD),role="admin",active=True)); db.commit()
@app.get("/api/health")
def health(): return {"status":"ok"}
@app.post("/api/auth/login")
def login(data:Login,db:Session=Depends(db_session)):
    u=db.query(User).filter(User.email==data.email.lower()).first()
    if not u or not u.active or not hasher.verify(data.password,u.password_hash): raise HTTPException(401,"Correo o contraseña incorrectos.")
    return {"access_token":token(u),"token_type":"bearer","user":UserOut.model_validate(u)}
@app.get("/api/auth/me",response_model=UserOut)
def me(u:User=Depends(auth)): return u
@app.get("/api/users",response_model=list[UserOut])
def users(_:User=Depends(admin),db:Session=Depends(db_session)): return db.query(User).order_by(User.id.desc()).all()
@app.post("/api/users",response_model=UserOut,status_code=201)
def add_user(data:UserCreate,_:User=Depends(admin),db:Session=Depends(db_session)):
    email=data.email.lower()
    if db.query(User).filter(User.email==email).first(): raise HTTPException(409,"Ese correo ya existe.")
    if data.role not in ("user","admin"): raise HTTPException(422,"Rol inválido.")
    u=User(name=data.name,email=email,password_hash=hasher.hash(data.password),role=data.role); db.add(u); db.commit(); db.refresh(u); return u
@app.patch("/api/users/{uid}",response_model=UserOut)
def edit_user(uid:int,data:UserPatch,a:User=Depends(admin),db:Session=Depends(db_session)):
    u=db.get(User,uid)
    if not u: raise HTTPException(404,"Usuario no encontrado.")
    d=data.model_dump(exclude_unset=True)
    if "password" in d and d["password"]: u.password_hash=hasher.hash(d.pop("password"))
    if "email" in d and d["email"]:
        email=str(d["email"]).lower()
        if db.query(User).filter(User.email==email,User.id!=uid).first(): raise HTTPException(409,"Correo ya registrado.")
        d["email"]=email
    if d.get("role") not in (None,"user","admin"): raise HTTPException(422,"Rol inválido.")
    if uid==a.id and d.get("active") is False: raise HTTPException(400,"No puedes desactivar tu propia cuenta.")
    for k,v in d.items(): setattr(u,k,v)
    db.commit(); db.refresh(u); return u
@app.delete("/api/users/{uid}")
def remove_user(uid:int,a:User=Depends(admin),db:Session=Depends(db_session)):
    u=db.get(User,uid)
    if not u: raise HTTPException(404,"Usuario no encontrado.")
    if uid==a.id: raise HTTPException(400,"No puedes eliminar tu propia cuenta.")
    db.delete(u); db.commit(); return {"message":"Cuenta eliminada."}
@app.get("/api/recipes")
def recipes(q:Optional[str]=None,category:Optional[str]=None,_:User=Depends(auth),db:Session=Depends(db_session)):
    query=db.query(Recipe)
    if q: query=query.filter(or_(Recipe.title.ilike(f"%{q}%"),Recipe.ingredients.ilike(f"%{q}%"),Recipe.description.ilike(f"%{q}%")))
    if category and category!="Todas": query=query.filter(Recipe.category==category)
    return [recipe_json(r) for r in query.order_by(Recipe.id.desc()).all()]
@app.post("/api/recipes",status_code=201)
def add_recipe(data:RecipeIn,u:User=Depends(auth),db:Session=Depends(db_session)):
    r=Recipe(**data.model_dump(),created_by=u.id); db.add(r); db.commit(); db.refresh(r); return recipe_json(r)
@app.put("/api/recipes/{rid}")
def edit_recipe(rid:int,data:RecipeIn,u:User=Depends(auth),db:Session=Depends(db_session)):
    r=db.get(Recipe,rid)
    if not r: raise HTTPException(404,"Receta no encontrada.")
    if u.role!="admin" and r.created_by!=u.id: raise HTTPException(403,"Solo puedes editar tus propias recetas.")
    for k,v in data.model_dump().items(): setattr(r,k,v)
    db.commit(); db.refresh(r); return recipe_json(r)
@app.delete("/api/recipes/{rid}")
def remove_recipe(rid:int,u:User=Depends(auth),db:Session=Depends(db_session)):
    r=db.get(Recipe,rid)
    if not r: raise HTTPException(404,"Receta no encontrada.")
    if u.role!="admin" and r.created_by!=u.id: raise HTTPException(403,"Solo puedes eliminar tus propias recetas.")
    db.delete(r); db.commit(); return {"message":"Receta eliminada."}
