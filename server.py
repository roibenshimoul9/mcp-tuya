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
        self._token_expire_at: float = 0

    @staticmethod
    def _require(name: str) -> str:
        value = os.getenv(name)
        if not value:
            raise RuntimeError(f"Missing required environment variable: {name}")
        return value

    def _sign(self, method: str, path: str, body: str, t: str, access_token="") -> str:
        content_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()

        string_to_sign = "\n".join([
            method.upper(),
            content_sha256,
            "",
            path
        ])

        message = f"{self.access_id}{access_token}{t}{string_to_sign}"

        return hmac.new(
            self.access_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest().upper()

    async def get_token(self):
        path = "/v1.0/token?grant_type=1"
        t = str(int(time.time() * 1000))

        headers = {
            "client_id": self.access_id,
            "t": t,
            "sign_method": "HMAC-SHA256",
            "sign": self._sign("GET", path, "", t),
        }

        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.base_url}/v1.0/token", params={"grant_type": 1}, headers=headers)
            data = r.json()

        if not data.get("success"):
            raise RuntimeError(data)

        self._access_token = data["result"]["access_token"]
        self._token_expire_at = time.time() + 6000

    async def request(self, method, path, body=None):
        if not self._access_token or time.time() > self._token_expire_at:
            await self.get_token()

        body_str = json.dumps(body or {}, separators=(",", ":"))

        t = str(int(time.time() * 1000))

        headers = {
            "client_id": self.access_id,
            "access_token": self._access_token,
            "t": t,
            "sign_method": "HMAC-SHA256",
            "sign": self._sign(method, path, body_str, t, self._access_token),
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            r = await client.request(
                method,
                f"{self.base_url}{path}",
                content=body_str if body else None,
                headers=headers,
            )
            data = r.json()

        if not data.get("success"):
            raise RuntimeError(data)

        return data


_tuya = TuyaCloud()


def client():
    return _tuya


# 🔥 הכי חשוב — פה התיקון
@mcp.tool()
async def list_devices() -> str:
    """Get all devices"""
    uid = os.getenv("TUYA_UID")
    data = await client().request("GET", f"/v1.0/users/{uid}/devices")
    return json.dumps(data["result"], ensure_ascii=False, indent=2)


@mcp.tool()
async def get_device_status(device_id: str) -> str:
    data = await client().request("GET", f"/v1.0/devices/{device_id}/status")
    return json.dumps(data["result"], ensure_ascii=False, indent=2)


@mcp.tool()
async def turn_on(device_id: str) -> str:
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        {
            "commands": [{"code": "switch_led", "value": True}]
        }
    )
    return json.dumps(data, indent=2)


@mcp.tool()
async def turn_off(device_id: str) -> str:
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        {
            "commands": [{"code": "switch_led", "value": False}]
        }
    )
    return json.dumps(data, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
