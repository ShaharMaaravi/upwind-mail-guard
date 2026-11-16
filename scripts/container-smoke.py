"""Exercise a locally built image with synthetic data; remove only our temporary containers."""

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "upwind-mail-guard:local"
TOKEN = secrets.token_urlsafe(32)
NAME = "upwind-smoke-" + secrets.token_hex(6)


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, timeout=60, **kwargs
    ).stdout.strip()


def request(origin, path, payload=None, authorized=False):
    headers = {"Content-Type": "application/json"}
    if authorized:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(
        origin + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def main():
    env = {**os.environ, "MAIL_GUARD_API_TOKEN": TOKEN}
    try:
        docker(
            "run",
            "-d",
            "--name",
            NAME,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=256m",
            "--cpus=0.5",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "-p",
            "127.0.0.1::8080",
            "-e",
            "MAIL_GUARD_API_TOKEN",
            IMAGE,
            env=env,
        )
        port = docker("port", NAME, "8080/tcp").rsplit(":", 1)[1]
        origin = "http://127.0.0.1:" + port
        for _ in range(100):
            try:
                if request(origin, "/healthz") == (200, {"status": "ok"}):
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise AssertionError("Container health check failed")
        assert docker("exec", NAME, "id", "-u") == "10001"
        docker(
            "exec",
            NAME,
            "python",
            "-c",
            "from pathlib import Path; assert not any(Path(p).exists() for p in "
            "['/app/.env','/app/.git','/app/addon','/app/tests','/app/backend/tests'])",
        )
        fixture = json.loads((ROOT / "fixtures/analysis-request.json").read_text())
        assert request(origin, "/v1/analyze", fixture)[0] == 401
        status, result = request(origin, "/v1/analyze", fixture, True)
        assert status == 200 and result["score"] == 95
        corpus = json.loads((ROOT / "fixtures/detection-cases.json").read_text())
        for case in corpus["cases"]:
            payload = json.loads(json.dumps(corpus["base_request"]))
            payload["message"].update(case.get("message", {}))
            if "attachments" in case:
                payload["attachments"] = case["attachments"]
            status, result = request(origin, "/v1/analyze", payload, True)
            assert status == 200 and result["score"] == case["expected"]["score"], case["id"]
        logs = subprocess.run(
            ["docker", "logs", NAME],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        ).stdout
        assert TOKEN not in logs and fixture["message"]["subject"] not in logs
        print(
            "PASS: non-root/read-only container, bounded resources, public health, "
            "auth rejection, 95-point fixture and 20 corpus cases."
        )
        print(
            "Container memory:", docker("stats", "--no-stream", "--format", "{{.MemUsage}}", NAME)
        )
    finally:
        subprocess.run(["docker", "rm", "-f", NAME], capture_output=True, timeout=15)
    missing_name = NAME + "-missing-secret"
    try:
        result = subprocess.run(
            ["docker", "run", "--name", missing_name, "--network=none", IMAGE],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode != 0 and "MAIL_GUARD_API_TOKEN" in result.stderr
        print("PASS: container refuses to start without its secret.")
    finally:
        subprocess.run(["docker", "rm", "-f", missing_name], capture_output=True, timeout=15)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(
            "Container verification failed. Inspect the local Docker setup "
            "and synthetic fixture checks.",
            file=sys.stderr,
        )
        sys.exit(1)
