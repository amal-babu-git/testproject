import uuid
from typing import Optional

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from pydantic import ConfigDict
from sqlalchemy import Column, String
from sqlmodel import Field, SQLModel


# Keep SQLAlchemyBaseUserTableUUID for type hinting and potential future use,
# but define fields explicitly within the SQLModel class.
class User(SQLModel, SQLAlchemyBaseUserTableUUID, table=True):
    """
    User model that integrates with FastAPI Users and SQLModel.
    Explicitly defines fields required by FastAPI Users using SQLModel.
    """

    __tablename__ = "users"

    # Model configuration
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Base fields required by FastAPI Users, defined explicitly with SQLModel
    # These override or satisfy the requirements of SQLAlchemyBaseUserTableUUID
    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,  # Add index for primary key
        nullable=False,
    )
    email: str = Field(
        index=True,
        nullable=False,
        unique=True,
        max_length=320,  # Match length from SQLAlchemyBaseUserTable
        sa_column_kwargs={"unique": True}  # Ensure unique constraint
    )
    hashed_password: str = Field(
        nullable=False,
        max_length=1024  # Match length from SQLAlchemyBaseUserTable
    )
    is_active: bool = Field(default=True, nullable=False)
    is_superuser: bool = Field(default=False, nullable=False)
    is_verified: bool = Field(default=False, nullable=False)

    # Custom fields specific to this application
    first_name: Optional[str] = Field(
        default=None, sa_column=Column(String(length=50), nullable=True)
    )
    last_name: Optional[str] = Field(
        default=None, sa_column=Column(String(length=50), nullable=True)
    )

    def __repr__(self) -> str:
        """String representation of the User object."""
        return f"<User id={self.id} email={self.email}>"
