# Mi Recetario — Angular + PrimeNG + FastAPI

## Incluye
- Login privado (sin registro público).
- Administrador: CRUD de usuarios y todas las recetas.
- Usuarios: ven todas las recetas y gestionan únicamente las propias.
- Tema claro/oscuro con detalles lilas.
- SQLite local integrado; PostgreSQL configurable para producción.

## Administrador inicial
Correo: `admin@recetario.local`  
Contraseña: `Rct-5yTejPFRWO!Lila`

Cambia la contraseña después del primer acceso. No compartas estas credenciales.

## Requisitos
Python 3.11+ (recomendado 3.12), Node.js 20.19+ o 22.12+, npm y VS Code.

## Ejecutar en Windows
### Backend
En una terminal:
```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --reload
```
API: http://127.0.0.1:8000  
Documentación: http://127.0.0.1:8000/docs  
La base `recetario.db` se crea automáticamente.

### Frontend (otra terminal)
```powershell
cd frontend
npm install
npm start
```
Abre http://localhost:4200. Mantén ambas terminales abiertas.

## Producción
Publica Angular en Vercel y FastAPI en Render/Railway (o servicio Python). Configura en el backend `DATABASE_URL` con PostgreSQL/Neon, `JWT_SECRET_KEY` nuevo y largo, y `CORS_ORIGINS` con el dominio exacto del frontend. Cambia `frontend/src/app/app.component.ts` para usar la URL pública del backend o configura un proxy/rewrite en Vercel. No uses SQLite en un entorno serverless para datos permanentes.

## GitHub
Desde la raíz: `git init`, `git add .`, `git commit -m "Proyecto inicial"`, agrega tu remoto y ejecuta `git push -u origin main`. `.env` y `*.db` están excluidos.
