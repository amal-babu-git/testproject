from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import JSONResponse

from app.auth.auth import (
    auth_backend,
    fastapi_users,
    current_active_user,
    current_superuser,
    get_user_manager
)
from app.auth.schemas import UserRead, UserCreate, UserUpdate, TokenResponse, RefreshTokenRequest
from app.auth.models import User
from app.auth.auth import UserManagerWithRefresh

# Create auth router
auth_router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Add routes for authentication - specify the custom response model for login
auth_router.include_router(
    fastapi_users.get_auth_router(auth_backend, requires_verification=False),
    prefix="/jwt",
)

# Add refresh token endpoint


@auth_router.post("/jwt/refresh", response_model=TokenResponse)
async def refresh_jwt(
    request: RefreshTokenRequest,
    user_manager: UserManagerWithRefresh = Depends(get_user_manager)
):
    """Refresh the access token using a refresh token."""
    new_access_token = await user_manager.refresh_access_token(request.refresh_token)
    if not new_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    # Note: We are returning the *old* refresh token.
    # For enhanced security, consider implementing refresh token rotation
    # where a new refresh token is issued along with the new access token.
    return TokenResponse(access_token=new_access_token, refresh_token=request.refresh_token)

# Add routes for registration
auth_router.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/register",
)

# Add routes for reset password
auth_router.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/reset-password",
)

# Add routes for verify
auth_router.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/verify",
)

# Create users router
users_router = APIRouter(
    prefix="/users",
    tags=["users"]
)

# Add routes for user management
users_router.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
)

# Protected routes example


@auth_router.get("/me")
async def authenticated_route(user: User = Depends(current_active_user)):
    """Example protected route that requires authentication."""
    return {"message": f"Hello {user.email}", "user_id": str(user.id)}


@auth_router.get("/admin")
async def admin_route(user: User = Depends(current_superuser)):
    """Example protected route that requires admin privileges."""
    return {"message": f"Hello admin {user.email}", "user_id": str(user.id)}
