import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tuya-poke")

# Tuya OpenAPI endpoints by data center
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
        region = os.getenv("TUYA_REGION", "eu").lower().strip()
        self.base_url = os.getenv("TUYA_BASE_URL", REGION_ENDPOINTS.get(region, region)).rstrip("/")

    @staticmethod
    def _require(name: str) -> str:
        value = os.getenv(name)
        if not value:
            raise RuntimeError(f"Missing required environment variable: {name}")
        return value

    def _sign(self, method: str, path_with_query: str, body: str, timestamp: str) -> str:
        # Tuya cloud signing for service-to-service calls
        content_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join([
            method.upper(),
            content_sha256,
            "",
            path_with_query,
        ])
        message = f"{self.access_id}{timestamp}{string_to_sign}"
        signature = hmac.new(
            self.access_secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest().upper()
        return signature

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

        query = ""
        if params:
            from urllib.parse import urlencode
            query = urlencode(params)
        path_with_query = path if not query else f"{path}?{query}"

        timestamp = str(int(time.time() * 1000))
        headers = {
            "client_id": self.access_id,
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
            "mode": "cors",
            "sign": self._sign(method, path_with_query, body_str, timestamp),
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
            code = data.get("code", "unknown")
            msg = data.get("msg", "Unknown Tuya error")
            raise RuntimeError(f"Tuya API error {code}: {msg}")
        return data


def client() -> TuyaCloud:
    return TuyaCloud()


@mcp.tool()
async def list_devices() -> str:
    """List all devices available to this Tuya cloud project."""
    data = await client().request("GET", "/v1.0/devices")
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
    """Send raw Tuya commands to a device. commands_json must be a JSON array like [{\"code\":\"switch_led\",\"value\":true}]"""
    commands = json.loads(commands_json)
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": commands},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def turn_on(device_id: str, switch_code: str = "switch_led") -> str:
    """Turn on a device using a boolean switch code. Default code is switch_led."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": switch_code, "value": True}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def turn_off(device_id: str, switch_code: str = "switch_led") -> str:
    """Turn off a device using a boolean switch code. Default code is switch_led."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": switch_code, "value": False}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def set_brightness(device_id: str, value: int, code: str = "bright_value_v2") -> str:
    """Set brightness for supported lights. Typical code is bright_value_v2, but some devices use bright_value."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": code, "value": value}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
async def set_color_temp(device_id: str, value: int, code: str = "temp_value_v2") -> str:
    """Set color temperature for supported lights. Typical code is temp_value_v2, but some devices use temp_value."""
    data = await client().request(
        "POST",
        f"/v1.0/iot-03/devices/{device_id}/commands",
        body={"commands": [{"code": code, "value": value}]},
    )
    return json.dumps(data, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
    
