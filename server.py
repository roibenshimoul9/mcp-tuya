import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "tuya-poke",
    host="0.0.0.0",
    port=int(os.getenv("PORT", "10000")),
)

REGION_ENDPOINTS = {
    "eu": "https://openapi.tuyaeu.com",
    "weu": "https://openapi-weaz.tuyaeu.com",
    "us": "https://openapi.tuyaus.com",
    "eus": "https://openapi-ueaz.tuyaus.com",
    "cn": "https://openapi.tuyacn.com",
    "in": "https://openapi.tuyain.com",
    "sg": "https://openapi-sg.iotbing.com",
}


class TuyaCloud:
    def __init__(self) -> None:
        self.access_id = self._require("TUYA_ACCESS_ID")
        self.access_secret = self._require("TUYA_ACCESS_SECRET")
        self.uid = self._require("TUYA_UID")

        region = os.getenv("TUYA_REGION", "eu").lower().strip()
        self.base_url = os.getenv(
            "TUYA_BASE_URL",
            REGION_ENDPOINTS.get(region, region),
        ).rstrip("/")

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expire_at: float = 0

    @staticmethod
    def _require(name: str) -> str:
        value = os.getenv(name)
        if not value:
            raise RuntimeError(f"Missing required environment variable: {name}")
        return value.strip()

    @staticmethod
    def _content_sha256(body: str) -> str:
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _string_to_sign(self, method: str, path_with_query: str, body: str) -> str:
        return "\n".join(
            [
                method.upper(),
                self._content_sha256(body),
                "",
                path_with_query,
            ]
        )

    def _sign_token_request(
        self,
        method: str,
        path_with_query: str,
        body: str,
        timestamp: str,
    ) -> str:
        string_to_sign = self._string_to_sign(method, path_with_query, body)
        message = f"{self.access_id}{timestamp}{string_to_sign}"
        return hmac.new(
            self.access_secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest().upper()

    def _sign_business_request(
        self,
        method: str,
        path_with_query: str,
        body: str,
        timestamp: str,
        access_token: str,
    ) -> str:
        string_to_sign = self._string_to_sign(method, path_with_query, body)
        message = f"{self.access_id}{access_token}{timestamp}{string_to_sign}"
        return hmac.new(
            self.access_secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest().upper()

    async def _get_token(self) -> None:
        path = "/v1.0/token"
        params = {"grant_type": "1"}
        body_str = ""
        path_with_query = f"{path}?grant_type=1"
        timestamp = str(int(time.time() * 1000))

        headers = {
            "client_id": self.access_id,
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
            "sign": self._sign_token_request("GET", path_with_query, body_str, timestamp),
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}{path}",
                params=params,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success", False):
            raise RuntimeError(f"Tuya token error {data.get('code')}: {data.get('msg')}")

        result = data["result"]
        self._access_token = result["access_token"]
        self._refresh_token = result.get("refresh_token")
        expire_time = int(result.get("expire_time", 7200))
        self._token_expire_at = time.time() + max(60, expire_time - 120)

    async def _refresh_access_token(self) -> None:
        if not self._refresh_token:
            await self._get_token()
            return

        path = f"/v1.0/token/{self._refresh_token}"
        body_str = ""
        timestamp = str(int(time.time() * 1000))

        headers = {
            "client_id": self.access_id,
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
            "sign": self._sign_token_request("GET", path, body_str, timestamp),
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.base_url}{path}", headers=headers)
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success", False):
            await self._get_token()
            return

        result = data["result"]
        self._access_token = result["access_token"]
        self._refresh_token = result.get("refresh_token")
        expire_time = int(result.get("expire_time", 7200))
        self._token_expire_at = time.time() + max(60, expire_time - 120)

    async def _ensure_token(self) -> str:
        if self._access_token and time.time() < self._token_expire_at:
            return self._access_token

        if self._refresh_token:
            await self._refresh_access_token()
        else:
            await self._get_token()

        if not self._access_token:
            raise RuntimeError("Failed to obtain Tuya access token")

        return self._access_token

    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        params = params or {}
        body = body or {}
        body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False) if body else ""

        query = urlencode(params) if params else ""
        path_with_query = path if not query else f"{path}?{query}"

        access_token = await self._ensure_token()
        timestamp = str(int(time.time() * 1000))

        headers = {
            "client_id": self.access_id,
            "access_token": access_token,
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
            "sign": self._sign_business_request(
                method,
                path_with_query,
                body_str,
                timestamp,
                access_token,
            ),
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(
                method.upper(),
                f"{self.base_url}{path}",
                params=params,
                content=body_str if body else None,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success", False):
            code = str(data.get("code", "unknown"))
            msg = data.get("msg", "Unknown Tuya error")

            if code in {"1010", "1011"}:
                await self._get_token()
                return await self.request(method, path, params=params, body=body)

            raise RuntimeError(f"Tuya API error {code}: {msg}")

        return data


_tuya_client = TuyaCloud()


def client() -> TuyaCloud:
    return _tuya_client


def require_uid() -> str:
    uid = os.getenv("TUYA_UID")
    if not uid:
        raise RuntimeError("Missing required environment variable: TUYA_UID")
    return uid.strip()


@mcp.tool()
async def list_devices() -> str:
    """List all devices linked to the Tuya user account."""
    uid = require_uid()
    data = await client().request("GET", f"/v1.0/users/{uid}/devices")
    return json.dumps(data.get("result", []), ensure_ascii=False, indent=2)


@mcp.tool()
async def get_device(device_id: str) -> str:
    """Get detailed information for one Tuya device by its device_id."""
    data = await client().request("GET", f"/v1.0/devices/{device_id}")
    return json.dumps(data.get("result", {}), ensure_ascii=False, indent=2)


@mcp.tool()
async def get_device_status(device_id: str) -> str:
    """Get the latest status list for one Tuya device by its device_id."""
    data = await client().request("GET", f"/v1.0/devices/{device_id}/status")
    return json.dumps(data.get("result", []), ensure_ascii=False, indent=2)


@mcp.tool()
async def send_commands(device_id: str, commands_json: str) -> str:
    """Send raw Tuya commands to a device. commands_json must be a JSON array."""
    commands = json.loads(commands_json)
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": commands},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def turn_on(device_id: str, switch_code: str = "switch_led") -> str:
    """Turn on a device using a boolean switch code."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": switch_code, "value": True}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def turn_off(device_id: str, switch_code: str = "switch_led") -> str:
    """Turn off a device using a boolean switch code."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": switch_code, "value": False}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def set_brightness(device_id: str, value: int, code: str = "bright_value_v2") -> str:
    """Set brightness for supported lights."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": code, "value": value}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def set_color_temp(device_id: str, value: int, code: str = "temp_value_v2") -> str:
    """Set color temperature for supported lights."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": code, "value": value}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
