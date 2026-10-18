
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from jose import jwt
from jose.exceptions import JWTError

app = FastAPI(title="JWT Verification Service")

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-mz2sc6pz.apps.exam.local"
ALGORITHM = "RS256"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/verify")
def verify_token(request: VerifyRequest):
    try:
        # Verify signature and all required registered claims.
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require_exp": True,
                "require_iss": True,
                "require_aud": True,
            },
        )

        # Return the claims from the verified token.
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims["aud"],
        }

    except (JWTError, ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=401,
            detail={"valid": False},
        )
