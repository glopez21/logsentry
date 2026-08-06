#!/usr/bin/env python3
"""sentryd mesh sidecar — starts w3bv01d peer, discovers hub on mesh, launches sentryd."""

import argparse
import asyncio
import json
import logging
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("mesh-discover")

CONFIG_DIR = pathlib.Path.home() / ".config" / "w3bv01d"
KEY_FILE = CONFIG_DIR / "identity.key"
PEER_ID_CACHE = CONFIG_DIR / "hub_peer_id.txt"


def load_peer_id() -> str | None:
    if KEY_FILE.exists():
        data = json.loads(KEY_FILE.read_text())
        return data.get("peer_id")
    return None


def save_hub_peer_id(peer_id: str):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PEER_ID_CACHE.write_text(peer_id.strip())


def load_hub_peer_id() -> str | None:
    if PEER_ID_CACHE.exists():
        return PEER_ID_CACHE.read_text().strip()
    return None


async def start_peer(coordinator: str, port: int, relay: str = "",
                     tun: bool = True, dht: bool = False) -> asyncio.subprocess.Process:
    cmd = [
        sys.executable, "-m", "peer.node",
        "--coordinator", coordinator,
        "--port", str(port),
    ]
    if tun:
        cmd.append("--tun")
    if dht:
        cmd.append("--dht")
    if relay:
        cmd.extend(["--relay", relay])

    log.info("starting w3bv01d peer: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    return proc


async def wait_for_tun(timeout: int = 30) -> str | None:
    """Wait for TUN interface to appear, return assigned IP."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "dev", "w3bv01d"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "inet " in line:
                    ip = line.strip().split()[1].split("/")[0]
                    log.info("TUN interface ready: %s", ip)
                    return ip
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        await asyncio.sleep(1)
    log.warning("TUN interface did not become ready within %ds", timeout)
    return None


async def run_mesh_discover():
    parser = argparse.ArgumentParser(description="sentryd mesh sidecar")
    parser.add_argument("--coordinator", default=os.getenv("MESH_COORDINATOR", "ws://127.0.0.1:8765"))
    parser.add_argument("--relay", default=os.getenv("MESH_RELAY", ""))
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--hub-peer-id", default=os.getenv("MESH_HUB_PEER_ID", ""),
                        help="Peer ID of the Augur hub on the mesh")
    parser.add_argument("--hub-port", type=int, default=8000,
                        help="Augur API port on the hub (default: 8000)")
    parser.add_argument("--sentryd-config", default="/etc/sentryd/sentryd.yaml",
                        help="Path to sentryd YAML config template")
    parser.add_argument("sentryd_args", nargs=argparse.REMAINDER,
                        help="Args passed through to sentryd binary")
    args = parser.parse_args()

    hub_peer_id = args.hub_peer_id
    if not hub_peer_id:
        cached = load_hub_peer_id()
        if cached:
            hub_peer_id = cached
            log.info("using cached hub peer ID: %s", hub_peer_id)

    if not hub_peer_id:
        log.error("hub peer ID not provided. Set MESH_HUB_PEER_ID or --hub-peer-id")
        sys.exit(1)

    save_hub_peer_id(hub_peer_id)

    peer_proc = await start_peer(
        coordinator=args.coordinator,
        port=args.port,
        relay=args.relay,
        tun=True,
    )

    tun_ip = await wait_for_tun(timeout=30)
    if not tun_ip:
        log.error("TUN not ready, aborting")
        peer_proc.kill()
        sys.exit(1)

    log.info("mesh peer online at %s, hub peer ID: %s", tun_ip, hub_peer_id)
    log.info("sentryd will connect to hub via mesh")

    hub_url = f"http://{hub_peer_id}:{args.hub_port}"

    config = {}
    if os.path.exists(args.sentryd_config):
        import yaml
        with open(args.sentryd_config) as f:
            config = yaml.safe_load(f) or {}

    if "hub" not in config:
        config["hub"] = {}
    config["hub"]["url"] = hub_url

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="sentryd-mesh-"
    )
    import yaml
    yaml.dump(config, tmp)
    tmp_path = tmp.name
    tmp.close()

    log.info("generated mesh config at %s with hub.url = %s", tmp_path, hub_url)

    sentryd_bin = args.sentryd_args.pop(0) if args.sentryd_args else "sentryd"
    sentryd_args = args.sentryd_args or ["daemon"]

    env = os.environ.copy()
    env["SENTRYD_CONFIG"] = tmp_path

    log.info("launching sentryd: %s %s", sentryd_bin, " ".join(sentryd_args))
    sentryd_proc = await asyncio.create_subprocess_exec(
        sentryd_bin, *sentryd_args,
        env=env,
    )

    def _forward(stream, label):
        async def _read():
            while True:
                line = await stream.readline()
                if not line:
                    break
                print(f"[{label}] {line.decode().rstrip()}")
        return _read

    async def _wait_both():
        await asyncio.gather(
            _forward(peer_proc.stdout, "w3bv01d")(),
            _forward(peer_proc.stderr, "w3bv01d:err")(),
            _forward(sentryd_proc.stdout, "sentryd")(),
            _forward(sentryd_proc.stderr, "sentryd:err")(),
            sentryd_proc.wait(),
        )

    def _shutdown(signum, frame):
        log.info("received signal %s, shutting down", signum)
        sentryd_proc.terminate()
        peer_proc.terminate()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    await _wait_both()

    peer_proc.terminate()
    try:
        os.unlink(tmp_path)
    except OSError:
        pass

    sys.exit(sentryd_proc.returncode or 0)


if __name__ == "__main__":
    asyncio.run(run_mesh_discover())
