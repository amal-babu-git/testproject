from typing import Optional, Any
from fastapi import BackgroundTasks, Request, Depends, Response
# Add OAuth2PasswordRequestForm import
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin, exceptions
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from fastapi_users.jwt import generate_jwt, decode_jwt, SecretType
from fastapi_users.exceptions import InvalidID, UserNotExists
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
import logging
import jwt
from datetime import timedelta, datetime, timezone

from app.auth.models import User
from app.auth.email import send_verification_email
from app.auth.schemas import UserCreate, TokenResponse
from app.core.db import get_session
from app.core.settings import settings

logger = logging.getLogger(__name__)

# User Database Dependency


async def get_user_db(session: AsyncSession = Depends(get_session)):
    yield SQLAlchemyUserDatabase(session, User)

# Bearer transport for JWT
bearer_transport = BearerTransport(tokenUrl="api/v1/auth/jwt/login")

# Custom JWT Strategy with Refresh Token support, the default JWTStrategy is extended to add refresh token functionality


class JWTRefreshStrategy(JWTStrategy):
    def __init__(
        self,
        secret: SecretType,
        lifetime_seconds: Optional[int],
        refresh_lifetime_seconds: Optional[int],
        token_audience: list[str] = ["fastapi-users:auth"],
        algorithm: str = "HS256",
        public_key: Optional[SecretType] = None,
    ):
        super().__init__(secret, lifetime_seconds, token_audience, algorithm, public_key)
        self.refresh_lifetime_seconds = refresh_lifetime_seconds
        self.token_audience_refresh = ["fastapi-users:refresh"]

    async def write_refresh_token(self, user: User) -> str:
        data = {"sub": str(user.id), "aud": self.token_audience_refresh}
        return generate_jwt(
            data, self.encode_key, self.refresh_lifetime_seconds, algorithm=self.algorithm
        )

    async def read_refresh_token(self, token: Optional[str]) -> Optional[dict[str, Any]]:
        if token is None:
            return None
        try:
            return decode_jwt(
                token, self.decode_key, self.token_audience_refresh, algorithms=[
                    self.algorithm]
            )
        except jwt.PyJWTError:
            return None


# JWT Strategy for authentication - returns the custom strategy
def get_jwt_strategy() -> JWTRefreshStrategy:
    return JWTRefreshStrategy(
        secret=settings.JWT_SECRET,
        lifetime_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_lifetime_seconds=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
    )


# Custom Authentication Backend to return both tokens
class CustomAuthenticationBackend(AuthenticationBackend):
    async def login(self, strategy: JWTRefreshStrategy, user: User) -> TokenResponse:
        """Generate access/refresh tokens and return them."""
        access_token = await strategy.write_token(user)
        refresh_token = await strategy.write_refresh_token(user)
        # The response object is not needed here as fastapi-users handles setting cookies/headers based on the transport
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    async def logout(self, strategy: JWTRefreshStrategy, user: User, token: str, response: Response) -> Any:
        # Optional: Implement token blacklisting here if needed
        # Logout signature might still need the response object depending on transport/strategy needs
        pass


# Authentication backend using the custom backend and strategy
auth_backend = CustomAuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

# User Manager for handling user operations - extended for refresh


class UserManagerWithRefresh(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.SECRET_KEY
    verification_token_secret = settings.SECRET_KEY
    # Define verification token lifetime (e.g., 1 day)
    verification_token_lifetime_seconds: int = 60 * 60 * 24

    def __init__(self, user_db, jwt_strategy: JWTRefreshStrategy):
        super().__init__(user_db)
        self.jwt_strategy = jwt_strategy

    async def create(self, user_create: UserCreate, safe: bool = False, request: Optional[Request] = None) -> User:
        user_dict = user_create.model_dump()
        user_dict["is_superuser"] = False
        user_dict["is_verified"] = False
        created_user = await super().create(UserCreate(**user_dict), safe, request)
        return created_user

    async def authenticate(
        self, credentials: OAuth2PasswordRequestForm
    ) -> Optional[User]:
        """
        Authenticate the user based on email and password.

        Overrides the default authenticate method to add an explicit check
        for the `is_verified` status before allowing login.

        :param credentials: The user credentials (username=email, password).
        :return: The authenticated user object if credentials are valid and
                 the user is active and verified. Returns None otherwise.
        """
        try:
            user = await self.get_by_email(credentials.username)
        except exceptions.UserNotExists:
            # Run the hasher to mitigate timing attack
            self.password_helper.hash(credentials.password)
            logger.debug(f"Login failed: User not found for email {credentials.username}")
            return None

        verified, updated_password_hash = self.password_helper.verify_and_update(
            credentials.password, user.hashed_password
        )
        if not verified:
            logger.debug(f"Login failed: Invalid password for user {user.id}")
            return None

        # Check if user is active
        if not user.is_active:
            logger.debug(f"Login failed: User {user.id} is inactive")
            return None

        if not user.is_verified:
            logger.debug(f"Login failed: User {user.id} is not verified")
            # Optionally, you could raise a specific exception here
            # raise exceptions.UserNotVerified()
            # Returning None is usually sufficient for login failure
            return None

        # Update password hash if needed
        if updated_password_hash is not None:
            await self.user_db.update(user, {"hashed_password": updated_password_hash})
            logger.debug(f"Password hash updated for user {user.id}")

        logger.debug(f"User {user.id} authenticated successfully")
        return user

    async def create_verification_token(self, user: User) -> str:
        """
        Generates a verification token for the user, matching fastapi-users internal logic.
        """
        data = {
            "sub": str(user.id),  # Use "sub" for user ID
            "email": user.email,
            "aud": self.verification_token_audience  # Use the audience attribute
        }
        token = generate_jwt(
            data,
            self.verification_token_secret,
            self.verification_token_lifetime_seconds,
        )
        return token

    async def on_after_register(
        self, user: User, request: Optional[Request] = None
    ) -> None:
        logger.info(f"User {user.id} has registered.")
        if request:
            try:
                # This now uses the updated create_verification_token method
                token = await self.create_verification_token(user)
                background_tasks = getattr(
                    request.state, "background_tasks", BackgroundTasks())
                await send_verification_email(user.email, token, background_tasks)
                logger.info(f"Verification email queued for user {user.id}")
            except Exception as e:
                logger.error(f"Failed to send verification email: {str(e)}")
        else:
            logger.warning(
                "Request object is None in on_after_register, cannot send verification email.")

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ) -> None:
        logger.info(
            f"User {user.id} has requested password reset. Token: {token}")

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ) -> None:
        # Note: The 'token' passed here is generated internally by fastapi-users
        # using the logic you requested for create_verification_token.
        # This method just handles sending the email with the provided token.
        logger.info(
            f"Verification requested for user {user.id}. Token: {token}")
        if not request:
            logger.warning("Request object is None in on_after_request_verify")
            background_tasks = BackgroundTasks()
            await send_verification_email(user.email, token, background_tasks)
            await background_tasks()
        else:
            background_tasks = getattr(
                request.state, "background_tasks", BackgroundTasks())
            await send_verification_email(user.email, token, background_tasks)
            logger.info(f"Verification email queued for user {user.id}")

    async def on_after_login(
        self,
        user: User,
        request: Optional[Request] = None,
        response: Optional[Response] = None,
    ) -> None:
        """
        Perform logic after successful user login.
        This method is called by fastapi-users after successful authentication.
        """
        logger.info(f"User {user.id} logged in successfully.")
        # Add your custom logic here, e.g.:
        # - Record login time
        # - Update user status
        # - Trigger other background tasks
        # Example:
        # if request:
        #     logger.info(f"Login request from IP: {request.client.host}")
        # if response:
        #     # You could potentially modify the response headers here, but be careful
        #     pass

    async def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        token_data = await self.jwt_strategy.read_refresh_token(refresh_token)
        if token_data is None:
            return None
        try:
            user_id = self.parse_id(token_data["sub"])
            user = await self.get(user_id)
            if not user or not user.is_active:
                return None
            new_access_token = await self.jwt_strategy.write_token(user)
            return new_access_token
        except (UserNotExists, InvalidID):
            return None


# User Manager dependency - returns the extended manager
async def get_user_manager(user_db=Depends(get_user_db), jwt_strategy: JWTRefreshStrategy = Depends(get_jwt_strategy)):
    yield UserManagerWithRefresh(user_db, jwt_strategy)

# Create FastAPIUsers instance - uses the extended manager
fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

# Current user dependencies (remain the same)
current_active_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)
current_verified_user = fastapi_users.current_user(active=True, verified=True)
