"""Resolve and pin outbound addresses to prevent access to server-local services."""
import asyncio
import ipaddress
import os
import socket


async def open_destination(host: str, port: int):
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise OSError('destination did not resolve')
    allow_private = os.environ.get('ALLOW_PRIVATE_DESTINATIONS') == '1'
    if not allow_private and any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('private/local destination is blocked')
    last_error = None
    for family, _, _, _, address in addresses:
        try:
            return await asyncio.open_connection(address[0], port, family=family)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError('destination is unreachable')
