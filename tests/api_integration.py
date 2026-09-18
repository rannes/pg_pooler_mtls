"""Exercise the same buttons a presenter uses through both published app APIs."""
import json
import subprocess
from urllib.request import Request, urlopen


def run():
    count = 0
    for app, port in (("app1", "8081"), ("app2", "8082")):
        published = subprocess.check_output(
            ["docker", "compose", "port", "ui", port], text=True).strip()
        base = f"http://{published}"
        for pooler in ("pgbouncer", "pgdog"):
            for action in ("identity", "read", "write", "impersonate", "cross_read", "set_role",
                           "direct_db", "direct_pooler_plain", "direct_pooler_tls"):
                request = Request(base + "/api/run", method="POST",
                                  data=json.dumps(dict(action=action, pooler=pooler)).encode(),
                                  headers={"Content-Type": "application/json", "Origin": base})
                with urlopen(request, timeout=30) as response:
                    result = json.load(response)
                expected = "allowed" if action in ("identity", "read", "write") else "blocked"
                assert result["passed"] is True, json.dumps(result, indent=2)
                assert result["outcome"] == expected, result
                assert result["app"] == app, result
                if expected == "allowed":
                    evidence = result["evidence"]
                    assert evidence["identity"]["current_user"] == app, evidence
                    assert evidence["identity"]["session_user"] == app, evidence
                    assert evidence["tls"]["ssl"] is True, evidence
                    assert evidence["tls"]["client_dn"] == f"/CN={pooler}-gateway", evidence
                print(f"PASS {app:4} {pooler:9} {action:20} {expected}", flush=True)
                count += 1
        with urlopen(base + "/api/events", timeout=3) as response:
            events = json.load(response)
        assert 18 <= len(events["events"]) <= events["limit"], events
        assert all(event["app"] == app for event in events["events"]), events
    print(f"PASS {count} app/pooler/action combinations; both event feeds verified")


if __name__ == "__main__":
    run()
