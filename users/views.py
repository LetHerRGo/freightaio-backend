from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user  # SupabaseUser
    return Response({
        "message": "You are authenticated!",
        "email": user.email,
        "sub": user.id,
        "claims": user.claims,
    })

@api_view(["GET"])
@permission_classes([AllowAny])
def ping(request):
    return Response({"ok": True})
