import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from topsecret.app import App
from topsecret.services.encryption import DecryptionError

api = FastAPI(title="Secrets API", description="API for encrypting and decrypting secrets", version="0.1.0")

app = App.get_instance()
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
static_dir = os.path.join(parent_dir, "static")

api.mount("/static", StaticFiles(directory=static_dir), name="static")

# TODO: move this to config 
MAX_SECRET_LENGTH = 4096


class EncryptRequest(BaseModel):
    """Request model for encryption."""

    secret: str = Field(..., min_length=1, description="The secret text to encrypt")
    passphrase: str | None = Field(None, description="Optional passphrase for encryption")


class EncryptResponse(BaseModel):
    """Response model for encryption."""

    hash: str = Field(..., description="The hash value of the encrypted secret")
    decrypt_url: str = Field(..., description="The URL to decrypt this secret")


class DecryptRequest(BaseModel):
    """Request model for decryption."""

    passphrase: str | None = Field(None, description="Optional passphrase for decryption")


class DecryptResponse(BaseModel):
    """Response model for decryption."""

    secret: str = Field(..., description="The decrypted secret")


def get_base_url(request: Request) -> str:
    """Extract base URL from request."""
    return str(request.base_url).rstrip("/")


def get_theme_path(name: str) -> str:
    """Get path to the HTML skin/theme."""
    filename = os.path.basename(name)
    theme_name = filename + ".html"

    themes_dir = os.path.join(static_dir, "themes")
    requested_theme_path = os.path.join(themes_dir, theme_name)
    default_theme_path = os.path.join(themes_dir, "default.html")

    if os.path.isfile(requested_theme_path):
        return requested_theme_path

    if os.path.isfile(default_theme_path):
        return default_theme_path

    raise HTTPException(status_code=500, detail="Server configuration error: Default theme file is missing.")


@api.post("/encrypt", response_model=EncryptResponse, tags=["encryption"])
async def encrypt_secret(request: EncryptRequest, base_url: str = Depends(get_base_url)) -> EncryptResponse:
    """Encrypt a secret."""
    try:
        data = request.secret.encode("utf-8")
    except UnicodeEncodeError as e:
        raise HTTPException(
            status_code=400, detail="Invalid secret format. Only UTF-8 encoded strings are allowed."
        ) from e

    _, hash_value = app.encryption_service.encrypt(data, request.passphrase)
    decrypt_url = f"{base_url}?hash={hash_value}"
    return EncryptResponse(hash=hash_value, decrypt_url=decrypt_url)


@api.post("/decrypt/{hash_value}", response_model=DecryptResponse, tags=["decryption"])
async def decrypt_secret(hash_value: str, request: DecryptRequest) -> DecryptResponse:
    """Decrypt a secret."""
    try:
        decrypted_text = app.encryption_service.decrypt(hash_value, request.passphrase)
        return DecryptResponse(secret=decrypted_text)
    except DecryptionError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e


@api.get("/", response_class=HTMLResponse, tags=["ui"])
async def root(theme: str | None = None) -> str:
    """Serve the HTML frontend."""
    theme = theme or "default"
    html_path = get_theme_path(theme)
    with open(html_path) as f:
        return f.read()


@api.get("/api/info", tags=["info"])
async def api_info() -> dict:
    """Return API information."""
    return {
        "name": "TopSecret Encryptor API",
        "version": "1.0.0",
        "endpoints": {"encrypt": "/encrypt", "decrypt": "/decrypt/{hash}"},
    }
