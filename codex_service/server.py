"""Private HTTP facade. Only the DMS server can reach authenticated operations."""
import os
import secrets
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from .runtime import CodexRuntime, CodexError

runtime = CodexRuntime()


@asynccontextmanager
async def lifespan(app):
    if len(os.getenv('CODEX_SERVICE_TOKEN', '')) < 32:
        raise RuntimeError('CODEX_SERVICE_TOKEN fehlt.')
    try:
        await runtime.ensure()
        yield
    finally:
        await runtime.close()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def authorized(x_codex_token: str = Header(default='')):
    expected = os.getenv('CODEX_SERVICE_TOKEN', '')
    if len(expected) < 32 or not secrets.compare_digest(x_codex_token, expected):
        raise HTTPException(403, 'Nicht autorisiert.')


@app.middleware('http')
async def private_requests(request: Request, call_next):
    if request.url.path != '/health':
        try:
            authorized(request.headers.get('x-codex-token', ''))
        except HTTPException:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail': 'Nicht autorisiert.'}, status_code=403)
    length = request.headers.get('content-length')
    if length and (not length.isdigit() or int(length) > 128 * 1024):
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'Anfrage zu groß.'}, status_code=413)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.exception_handler(CodexError)
async def codex_failure(request, exc):
    from fastapi.responses import JSONResponse
    return JSONResponse({'detail': str(exc)}, status_code=503)


class ExtractInput(BaseModel):
    text: str = Field(min_length=1, max_length=30000)
    model: str | None = Field(default=None, max_length=150, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$')


@app.get('/health')
async def health():
    if not runtime.process or runtime.process.returncode is not None:
        raise HTTPException(503, 'Codex-Dienst wird gestartet.')
    return {'status': 'ok'}


@app.get('/v1/status', dependencies=[Depends(authorized)])
async def status():
    return await runtime.status(include_usage=True)


@app.get('/v1/models', dependencies=[Depends(authorized)])
async def models():
    return {'models': await runtime.models()}


@app.post('/v1/login', dependencies=[Depends(authorized)])
async def login():
    return await runtime.start_login()


@app.post('/v1/logout', dependencies=[Depends(authorized)])
async def logout():
    await runtime.logout()
    return {'ok': True}


@app.post('/v1/extract', dependencies=[Depends(authorized)])
async def extract(data: ExtractInput):
    return {'metadata': await runtime.extract(data.text, data.model)}
