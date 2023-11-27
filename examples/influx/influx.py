#!/usr/bin/env python3

########################
#
# Config items
#
########################
import asyncio
import json
import logging
import os
import sys
from binascii import a2b_hex, b2a_hex
from contextlib import AsyncExitStack

import aiohttp
from aioedgeos import EdgeOS, TaskEvery, find_subkey
from influxdb_client import InfluxDBClient, Point

DEBUG_MODE = os.environ.get("DEBUG_MODE")

logging.basicConfig(format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("edgeos-exporter")
if DEBUG_MODE:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


"""
If you want to replace the system hostname with something
else and don't want to change the router config you can
change it here
"""
ROUTER_TAGNAME = os.environ.get("ROUTER_TAGNAME", None)

""" Credentials to get into the webUI """
ROUTER_USERNAME = os.environ["ROUTER_USERNAME"]  # username
ROUTER_PASSWORD = os.environ["ROUTER_PASSWORD"]  # password123
ROUTER_URL = os.environ["ROUTER_URL"]  # https://192.168.1.1

""" 
TRUE for SSL that will validate or the base64 sha256
fingerprint for the host
"""
ROUTER_SSL = os.environ.get("ROUTER_SSL", "f" * 64).lower()  # Default to enforcing ssl

""" InfluxDB settings """
INFLUX_URL = os.environ["INFLUX_URL"]  # https://influxdb.local:1234
INFLUX_BUCKET = os.environ["INFLUX_BUCKET"]  # abc
""" optional influx settings """
INFLUX_CLIENT_ARGS = os.environ.get("INFLUX_CLIENT_ARGS", "{}")  #  {"org": "default", "cert_file": "influx.crt", "cert_key_file": "influx.key"}


ssl_check = True
if isinstance(ROUTER_SSL, str) and len(ROUTER_SSL) == 64:
    # presume this is a fingerprint
    ssl_check = aiohttp.Fingerprint(a2b_hex(ROUTER_SSL))
elif ROUTER_SSL in ["no", "false"]:
    ssl_check = False
elif ROUTER_SSL in ["yes", "true"]:
    ssl_check = True
else:
    raise Exception(f"ROUTER_SSL {ROUTER_SSL} is invalid")

influx_kwargs = json.loads(INFLUX_CLIENT_ARGS)
influx_kwargs_hidden_secrets = {
    k: v
    for k, v in influx_kwargs.items()
    if k
    in (
        "org",
        "timeout",
        "verify_ssl",
        "ssl_ca_cert",
        "cert_file",
        "cert_key_file",
        "connection_pool_maxsize",
        "auth_basic",
    )
}

for secret_opt in ("cert_key_password", "token"):
    if secret_opt in influx_kwargs:
        influx_kwargs_hidden_secrets[secret_opt] = influx_kwargs[secret_opt][:2]


def process_system_stats(value, hostname):
    return (
        Point("system_stat")
        .tag("router", hostname)
        .field("cpu", value["cpu"])
        .field("mem", value["mem"])
        .field("uptime", value["uptime"])
    )


if_fields = [
    "rx_packets",
    "rx_bytes",
    "rx_errors",
    "rx_dropped",
    "tx_packets",
    "tx_bytes",
    "tx_errors",
    "tx_dropped",
]


def process_interfaces(value, hostname):
    for interface, data in value.items():
        stats = data["stats"]
        datapoint = (
            Point("interface")
            .tag("router", hostname)
            .tag("ifname", interface)
            .tag("addresses", ",".join(data.get("addresses", [])))
        )
        for k, v in stats.items():
            if k not in if_fields:
                continue
            datapoint.field(k, int(v))
        yield datapoint


ip2mac1 = {}
ip2mac2 = {}


def config_extract_map(config):
    ip2mac = {}
    for mapping in find_subkey(config, "static-mapping"):
        for name, value in mapping.items():
            ip2mac[value["ip-address"]] = {
                "ip": value["ip-address"],
                "mac": value["mac-address"],
                "name": name,
            }
    global ip2mac1
    ip2mac1.update(ip2mac)
    return ip2mac


def leases_extract(leases):
    ip2mac = {}
    try:
        for lan_lease in leases["dhcp-server-leases"].values():
            if not isinstance(lan_lease, dict):
                continue
            for ip, value in lan_lease.items():
                name = value["client-hostname"]
                if len(name) == 0:
                    name = "-"
                ip2mac[ip] = {"ip": ip, "mac": value["mac"], "name": name}
    except:
        pass
    global ip2mac2
    ip2mac2.update(ip2mac)
    return ip2mac


def best_id_name(ip):
    if ip in ip2mac1:
        return ip2mac1[ip]["mac"], ip2mac1[ip]["name"]
    if ip in ip2mac2:
        return ip2mac2[ip]["mac"], ip2mac2[ip]["name"]
    return ip, "UNK"


def process_export(value, hostname):
    datapoint = Point("client").tag("router", hostname).field("num_active", len(value))
    yield datapoint
    if not isinstance(value, dict):
        return
    for ip, dpi in value.items():
        oid, name = best_id_name(ip)
        for app, value in dpi.items():
            if int(value["rx_rate"]) == 0 and int(value["tx_rate"]) == 0:
                continue
            app, cat = app.split("|", 1)
            datapoint = (
                Point("dpi")
                .tag("router", hostname)
                .tag("client_id", oid)
                .tag("client_name", name)
                .tag("dpi", app)
                .tag("dpi_category", cat)
            )
            datapoint.field("rx_bytes", int(value["rx_bytes"]))
            datapoint.field("tx_bytes", int(value["tx_bytes"]))
            yield datapoint


def process_users(value, hostname):
    for user_type, value in value.items():
        yield (
            Point("user")
            .tag("router", hostname)
            .tag("user_type", user_type)
            .field("count", len(value))
        )


async def dhcp_refresh(router):
    await router.dhcp_leases()
    leases_extract(router.sysdata["dhcp_leases"])


async def main_loop():
    async with AsyncExitStack() as stack:
        try:
            """ROUTER SETUP"""
            logger.info(
                "connecting to router %s with user %s", ROUTER_URL, ROUTER_USERNAME
            )
            router = await stack.enter_async_context(
                EdgeOS(ROUTER_USERNAME, ROUTER_PASSWORD, ROUTER_URL, ssl=ssl_check)
            )
            await router.config()
            config_extract_map(router.sysconfig)

            hostname = ROUTER_TAGNAME or router.sysconfig["system"]["host-name"]

            """ Sanity check host """
            try:
                if (
                    router.sysconfig["system"]["traffic-analysis"]["dpi"] == "enable"
                    and router.sysconfig["system"]["traffic-analysis"]["export"]
                    == "enable"
                ):
                    logger.debug("%s appears to have DPI enabled", hostname)
            except:
                logger.warning(
                    "%s does not appear to have dpi enabled. Functionality will be limited",
                    hostname,
                )

            logger.info("connected to router %s", hostname)

            logger.info("launching dhcp scraper")
            await stack.enter_async_context(
                TaskEvery(dhcp_refresh, router, interval=600)
            )

            """ INFLUX SETUP """
            logger.info(f"connecting to InfluxDB %s", INFLUX_URL)
            client = InfluxDBClient(
                url=INFLUX_URL,
                **influx_kwargs,
            )

            # for _, log in client.conf.loggers.items():
            #     log.setLevel(logging.DEBUG)
            #     log.addHandler(logging.StreamHandler(sys.stdout))

            async def write_metrics(metrics):
                with client.write_api() as write_client:
                    return write_client.write(INFLUX_BUCKET, influx_kwargs["org"], metrics)

            # Don't need this for InfluxDB v2
            # await client.create_database(INFLUX_DB)
            logger.info("connected to InfluxDB")

            logger.info("starting main websocket loop")
            async for payload in router.stats(
                subs=["export", "interfaces", "system-stats", "config-change"]
            ):
                for key, value in payload.items():
                    if not isinstance(value, dict):
                        logger.warning(
                            "%s for %s isn't a dict, would likely cause trouble in processing skipping",
                            value,
                            key,
                        )
                        continue
                    if key == "system-stats":
                        await write_metrics(process_system_stats(value, hostname))
                    elif key == "interfaces":
                        await write_metrics(process_interfaces(value, hostname))
                    elif key == "export":
                        await write_metrics(process_export(value, hostname))
                    elif key == "users":
                        await write_metrics(process_users(value, hostname))
                    elif key == "config-change" and value["commit"] == "ended":
                        global ip2mac1
                        ip2mac1 = config_extract_map(router.sysconfig)
                        hostname = (
                            ROUTER_TAGNAME or router.sysconfig["system"]["host-name"]
                        )
                    else:
                        logger.debug(
                            "got datapoint %s but I don't know how to handle it, ignoring",
                            key,
                        )
        except aiohttp.client_exceptions.ServerFingerprintMismatch as e:
            fphash = b2a_hex(e.got).decode()
            print(
                f"""
===============   TLS/SSL HASH MISMATCH ===============
Server replied with different fingerprint hash of {fphash}, it's likely you didn't setup the 
ssl for your router.  If this is the case please update your environment with the following.

ROUTER_SSL={fphash}
===============   TLS/SSL HASH MISMATCH ==============="""
            )


if __name__ == "__main__":
    rh = ROUTER_TAGNAME or "**get hostname from system config**"

    print(
        f"""
    ================================================
    ROUTER_TAGNAME     = {rh}
    ROUTER_USERNAME    = {ROUTER_USERNAME}
    ROUTER_PASSWORD    = **HIDDEN**
    ROUTER_URL         = {ROUTER_URL}
    ROUTER_SSL         = {ROUTER_SSL}
    - ssl_check       -> {ssl_check!r}
    INFLUX_HOST        = {INFLUX_URL}
    INFLUX_CLIENT_ARGS = {influx_kwargs_hidden_secrets}
    ================================================
    """
    )
    sys.stdout.flush()
    asyncio.run(main_loop())
