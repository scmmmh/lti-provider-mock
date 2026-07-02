# SPDX-FileCopyrightText: 2026-present Mark Hall <mark.hall@work.room3b.eu>
#
# SPDX-License-Identifier: MIT
"""LTI provider mock settings."""

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthUser(BaseModel):
    """Authentication user for BASIC authentication."""

    username: str
    password: str


class Course(BaseModel):
    """Configured course."""

    id: str
    name: str
    users: list[str] = []


class User(BaseModel):
    """Configured LTI user."""

    id: str
    given_name: str
    family_name: str
    email: str
    restricted: str | None = None


class LTISettings(BaseModel):
    """LTI settings."""

    iss: str
    login_url: str
    launch_url: str


class Settings(BaseSettings):
    """LTI provider mock settings."""

    auth_users: list[AuthUser] = []
    users: list[User] = []
    courses: list[Course] = []
    lti: LTISettings

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="LTI_PROVIDER_MOCK__",
        env_nested_delimiter="__",
        extra="ignore",
    )


settings = Settings()
