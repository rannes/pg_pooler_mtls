"""Verify the running deployment boundaries, never merely grep configuration."""
import json
import subprocess
import unittest


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def inspect(service):
    container = command("docker", "compose", "ps", "-q", service)
    if not container:
        raise AssertionError(f"{service} is not running")
    return json.loads(command("docker", "inspect", container))[0]


class DeploymentTests(unittest.TestCase):
    def test_app_processes_have_no_keys_or_credentials(self):
        for app in ("app1", "app2"):
            info = inspect(app)
            self.assertEqual(info["Config"]["User"], "10001:10001")
            self.assertEqual(info["Mounts"], [])
            self.assertFalse(any("PASSWORD=" in value or "PGPASSFILE=" in value
                                 for value in info["Config"]["Env"]))
            self.assertTrue(info["HostConfig"]["ReadonlyRootfs"])
            self.assertEqual(info["HostConfig"]["NetworkMode"], "container:" + inspect("envoy-" + app)["Id"])

    def test_only_loopback_ui_ports_are_published(self):
        for service in ("ui", "app1", "app2", "envoy-app1", "envoy-app2", "postgres", "pgbouncer", "pgdog"):
            info = inspect(service)
            bindings = info["HostConfig"]["PortBindings"] or {}
            if service == "ui":
                self.assertEqual(set(bindings), {"8081/tcp", "8082/tcp"})
                self.assertTrue(all(binding["HostIp"] == "127.0.0.1"
                                    for port in bindings.values() for binding in port))
            else:
                self.assertFalse(bindings, service)

    def test_apps_are_not_on_the_backend_or_each_others_network(self):
        database_networks = set(inspect("postgres")["NetworkSettings"]["Networks"])
        first = set(inspect("envoy-app1")["NetworkSettings"]["Networks"])
        second = set(inspect("envoy-app2")["NetworkSettings"]["Networks"])
        self.assertTrue(database_networks)
        self.assertFalse(first & database_networks)
        self.assertFalse(second & database_networks)
        self.assertFalse(first & second)
        for network in database_networks | first | second:
            self.assertTrue(json.loads(command("docker", "network", "inspect", network))[0]["Internal"])

    def test_runtime_roles_have_no_passwords_or_escalation_memberships(self):
        query = "SELECT count(*) FROM pg_roles WHERE rolname IN ('app1','app2') AND rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls"
        self.assertEqual(command("docker", "compose", "exec", "-T", "-u", "postgres", "postgres",
                                 "psql", "-d", "productdb", "-tAc", query), "2")
        query = "SELECT count(*) FROM pg_authid WHERE rolname IN ('app1','app2','postgres') AND rolpassword IS NOT NULL"
        self.assertEqual(command("docker", "compose", "exec", "-T", "-u", "postgres", "postgres",
                                 "psql", "-d", "productdb", "-tAc", query), "0")
        query = "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN ('app1','app2')"
        self.assertEqual(command("docker", "compose", "exec", "-T", "-u", "postgres", "postgres",
                                 "psql", "-d", "productdb", "-tAc", query), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
