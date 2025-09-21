from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import os
import jwt  # PyJWT

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
EXPECTED_ISS = f"{SUPABASE_URL}/auth/v1" if SUPABASE_URL else None


class SupabaseUser:
    """Minimal user-like object backed by Supabase JWT claims."""
    def __init__(self, claims):
        self.claims = claims
        self.id = claims.get("sub")
        self.email = claims.get("email")

    @property
    def is_authenticated(self):
        return True

    def __str__(self):
        return self.email or self.id or "SupabaseUser"


class SupabaseJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None  # no token → let DRF treat as unauthenticated

        token = auth.split(" ", 1)[1].strip()

        if not SUPABASE_JWT_SECRET:
            raise AuthenticationFailed("Server misconfigured: missing SUPABASE_JWT_SECRET")

        try:
            # Validate HS256 JWT issued by Supabase
            claims = jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            # Optional: validate issuer matches your project
            if EXPECTED_ISS and claims.get("iss") != EXPECTED_ISS:
                raise AuthenticationFailed("Invalid issuer")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f"Invalid token: {e}")

        # DRF expects (user, auth). `auth` can be the raw token.
        return (SupabaseUser(claims), token)
