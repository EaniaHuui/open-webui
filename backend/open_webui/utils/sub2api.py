import base64
import hashlib
import json
import logging
import time
from typing import Optional
from urllib.parse import urlsplit

import aiohttp
from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from open_webui.config import SUB2API_API_KEY_ENCRYPTION_KEY
from open_webui.constants import ERROR_MESSAGES
from open_webui.models.users import UserModel, Users

log = logging.getLogger(__name__)

SUB2API_PROVIDER = 'sub2api'
SUB2API_INFO_KEY = 'sub2api'


class Sub2APIClient:
    def __init__(self, *, base_url: str, timeout: int):
        if not base_url:
            raise ValueError('SUB2API_BASE_URL is not configured')
        self.base_url = base_url.rstrip('/')
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _request(self, method: str, path: str, *, token: Optional[str] = None, json_body: Optional[dict] = None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        async with aiohttp.ClientSession(timeout=self.timeout, trust_env=True) as session:
            async with session.request(
                method,
                f'{self.base_url}{path}',
                json=json_body,
                headers=headers,
            ) as response:
                try:
                    payload = await response.json()
                except Exception:
                    payload = {'message': await response.text()}

                if response.status >= 400:
                    detail = None
                    if isinstance(payload, dict):
                        detail = payload.get('message') or payload.get('detail')
                        if not detail and isinstance(payload.get('error'), dict):
                            detail = payload['error'].get('message')
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST if response.status in (401, 403) else response.status,
                        detail=detail or ERROR_MESSAGES.INVALID_CRED,
                    )

                if isinstance(payload, dict) and 'data' in payload:
                    return payload['data']
                return payload

    async def login(self, email: str, password: str) -> dict:
        payload = await self._request(
            'POST',
            '/api/v1/auth/login',
            json_body={'email': email, 'password': password},
        )
        if payload.get('requires_2fa'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Sub2API account requires 2FA and cannot complete delegated sign-in.',
            )
        if not payload.get('access_token'):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_CRED)
        return payload

    async def get_current_user(self, token: str) -> dict:
        return await self._request('GET', '/api/v1/auth/me', token=token)

    async def list_api_keys(self, token: str) -> list[dict]:
        payload = await self._request('GET', '/api/v1/keys?page=1&page_size=100', token=token)
        if isinstance(payload, dict):
            return payload.get('items', [])
        return payload if isinstance(payload, list) else []

    async def create_api_key(self, token: str, name: str) -> dict:
        return await self._request('POST', '/api/v1/keys', token=token, json_body={'name': name})


class Sub2APIKeyCipher:
    def __init__(self):
        key = SUB2API_API_KEY_ENCRYPTION_KEY
        if not key:
            raise ValueError('SUB2API_API_KEY_ENCRYPTION_KEY is not set')
        if len(key) != 44:
            key = base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()).decode()
        self.fernet = Fernet(key.encode())

    def encrypt(self, value: str) -> str:
        return self.fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        return self.fernet.decrypt(value.encode()).decode()


_sub2api_key_cipher = Sub2APIKeyCipher()


def mask_api_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if len(value) <= 8:
        return '*' * len(value)
    return f'{value[:4]}...{value[-4:]}'


def _default_sub2api_info() -> dict:
    return {
        'auth': {
            'access_token': None,
            'token_type': None,
            'expires_in': None,
            'last_login_at': None,
        },
        'profile': {
            'linked': False,
            'external_user_id': None,
            'external_email': None,
            'display_name': None,
            'linked_at': None,
            'last_profile_sync_at': None,
        },
        'key_cache': {
            'selected_strategy': None,
            'selected_key_id': None,
            'selected_key_name': None,
            'masked_key_hint': None,
            'cached_api_key': None,
            'last_key_sync_at': None,
        },
    }


LEGACY_SUB2API_FIELD_MAP = {
    'access_token': ('auth', 'access_token'),
    'token_type': ('auth', 'token_type'),
    'expires_in': ('auth', 'expires_in'),
    'last_login_at': ('auth', 'last_login_at'),
    'linked': ('profile', 'linked'),
    'external_user_id': ('profile', 'external_user_id'),
    'external_email': ('profile', 'external_email'),
    'display_name': ('profile', 'display_name'),
    'linked_at': ('profile', 'linked_at'),
    'last_profile_sync_at': ('profile', 'last_profile_sync_at'),
    'selected_strategy': ('key_cache', 'selected_strategy'),
    'selected_key_id': ('key_cache', 'selected_key_id'),
    'selected_key_name': ('key_cache', 'selected_key_name'),
    'masked_key_hint': ('key_cache', 'masked_key_hint'),
    'cached_api_key': ('key_cache', 'cached_api_key'),
    'last_key_sync_at': ('key_cache', 'last_key_sync_at'),
}


CANONICAL_SUB2API_SECTIONS = ('auth', 'profile', 'key_cache')


def normalize_sub2api_info(raw_info: Optional[dict]) -> dict:
    normalized = _default_sub2api_info()

    if not isinstance(raw_info, dict):
        return normalized

    for section in CANONICAL_SUB2API_SECTIONS:
        section_value = raw_info.get(section)
        if isinstance(section_value, dict):
            normalized[section].update(section_value)

    for legacy_key, (section, key) in LEGACY_SUB2API_FIELD_MAP.items():
        if legacy_key in raw_info and normalized[section].get(key) is None:
            normalized[section][key] = raw_info.get(legacy_key)

    normalized['profile']['linked'] = bool(normalized['profile'].get('linked'))
    return normalized


def merge_sub2api_info(existing_info: Optional[dict], updates: Optional[dict] = None) -> dict:
    normalized = normalize_sub2api_info(existing_info)
    if not isinstance(updates, dict):
        return normalized

    for section in CANONICAL_SUB2API_SECTIONS:
        section_updates = updates.get(section)
        if isinstance(section_updates, dict):
            normalized[section].update(section_updates)

    for legacy_key, (section, key) in LEGACY_SUB2API_FIELD_MAP.items():
        if legacy_key in updates:
            normalized[section][key] = updates.get(legacy_key)

    normalized['profile']['linked'] = bool(normalized['profile'].get('linked'))
    return normalized


def get_sub2api_info(user: UserModel) -> dict:
    info = user.info or {}
    sub2api_info = info.get(SUB2API_INFO_KEY)
    return normalize_sub2api_info(sub2api_info)


async def update_sub2api_info(user_id: str, info: dict, *, db: Optional[AsyncSession] = None) -> Optional[UserModel]:
    user = await Users.get_user_by_id(user_id, db=db)
    if not user:
        return None

    current_info = user.info or {}
    current_info[SUB2API_INFO_KEY] = merge_sub2api_info(current_info.get(SUB2API_INFO_KEY), info)
    return await Users.update_user_by_id(user_id, {'info': current_info}, db=db)


async def link_sub2api_user(
    user: UserModel,
    profile: dict,
    *,
    strategy: str,
    db: Optional[AsyncSession] = None,
) -> Optional[UserModel]:
    sub2api_info = get_sub2api_info(user)
    now = int(time.time())
    profile_name = profile.get('username') or profile.get('email') or user.name

    updated_info = merge_sub2api_info(
        sub2api_info,
        {
            'profile': {
                'linked': True,
                'external_user_id': profile.get('id'),
                'external_email': profile.get('email', user.email),
                'display_name': profile_name,
                'linked_at': sub2api_info['profile'].get('linked_at') or now,
                'last_profile_sync_at': now,
            },
            'key_cache': {
                'selected_strategy': strategy,
            },
        },
    )

    updated_user = await Users.update_user_by_id(
        user.id,
        {
            'email': profile.get('email', user.email).lower(),
            'name': profile_name,
            'info': {**(user.info or {}), SUB2API_INFO_KEY: updated_info},
        },
        db=db,
    )
    return updated_user


async def resolve_sub2api_api_key(
    request,
    user: UserModel,
    *,
    db: Optional[AsyncSession] = None,
    force_refresh: bool = True,
) -> str:
    config = request.app.state.config
    client = Sub2APIClient(
        base_url=config.SUB2API_BASE_URL,
        timeout=config.SUB2API_REQUEST_TIMEOUT,
    )

    info = get_sub2api_info(user)
    access_token = info['auth'].get('access_token')
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Sub2API account is not linked for this Open WebUI user.',
        )

    keys = []
    if force_refresh:
        keys = await client.list_api_keys(access_token)
    if not keys and not force_refresh:
        keys = await client.list_api_keys(access_token)

    strategy = config.SUB2API_KEY_SELECTION_STRATEGY or 'first'
    selected_key = None
    if strategy == 'first' and keys:
        selected_key = keys[0]

    if not selected_key and not keys and config.SUB2API_AUTO_CREATE_KEY:
        selected_key = await client.create_api_key(access_token, config.SUB2API_AUTO_CREATE_KEY_NAME)
        keys = [selected_key]

    if not selected_key and keys:
        selected_key = keys[0]

    if not selected_key or not selected_key.get('key'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='No usable sub2api API key is available for this user.',
        )

    now = int(time.time())
    updated_info = {
        'profile': {
            'linked': True,
        },
        'key_cache': {
            'selected_strategy': strategy,
            'selected_key_id': selected_key.get('id'),
            'selected_key_name': selected_key.get('name'),
            'masked_key_hint': mask_api_key(selected_key.get('key')),
            'cached_api_key': _sub2api_key_cipher.encrypt(selected_key['key']),
            'last_key_sync_at': now,
        },
    }

    await update_sub2api_info(user.id, updated_info, db=db)
    return selected_key['key']


def normalize_sub2api_openai_base_url(url: Optional[str]) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None

    stripped_url = url.strip()
    if not stripped_url:
        return None

    parsed = urlsplit(stripped_url)
    if not parsed.scheme or not parsed.netloc:
        return stripped_url.rstrip('/')

    normalized_path = parsed.path.rstrip('/')
    if normalized_path.endswith('/v1'):
        normalized_path = normalized_path[:-3]
    normalized_path = normalized_path.rstrip('/')

    return parsed._replace(path=normalized_path, query='', fragment='').geturl().rstrip('/')


def is_sub2api_provider(config: Optional[dict], url: Optional[str], sub2api_openai_base_url: str) -> bool:
    if config and config.get('provider') == SUB2API_PROVIDER:
        return True
    if not url or not sub2api_openai_base_url:
        return False
    return normalize_sub2api_openai_base_url(url) == normalize_sub2api_openai_base_url(sub2api_openai_base_url)
