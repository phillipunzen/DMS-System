"""Private HTTP facade. Only the DMS server can reach authenticated operations."""
import os
import secrets
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
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
    body_limit = 32 * 1024 * 1024 if request.url.path == '/v1/extract' else 128 * 1024
    if length and (not length.isdigit() or int(length) > body_limit):
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'Anfrage zu groß.'}, status_code=413)
    original_receive = request._receive
    received = 0
    async def limited_receive():
        nonlocal received
        message = await original_receive()
        received += len(message.get('body', b''))
        if received > body_limit:
            raise HTTPException(413, 'Anfrage zu groß.')
        return message
    request._receive = limited_receive
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
    images: list[str] = Field(default_factory=list, max_length=50)

    @field_validator('images')
    @classmethod
    def local_images(cls, images):
        import base64
        total = 0
        for image in images:
            if not image.startswith('data:image/jpeg;base64,'):
                raise ValueError('Nur eingebettete JPEG-Seiten erlaubt.')
            try: payload = base64.b64decode(image.split(',', 1)[1], validate=True)
            except ValueError: raise ValueError('Ungültige Bilddaten.')
            total += len(payload)
            if not payload.startswith(b'\xff\xd8\xff') or total > 20 * 1024 * 1024:
                raise ValueError('Ungültige oder zu große Dokumentseiten.')
        return images


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
    if data.images:
        return {'metadata': await runtime.extract(data.text, data.model, data.images)}
    return {'metadata': await runtime.extract(data.text, data.model)}
