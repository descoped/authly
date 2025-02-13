from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class UserModel(BaseModel):
    id: UUID
    username: str
    email: str
    password_hash: str
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    is_verified: bool = False
    is_admin: bool = False
