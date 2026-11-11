"""Render the operator chart and enforce its rollout contract."""

from pathlib import Path
import subprocess
import unittest

import yaml


CHART = Path(__file__).resolve().parent


class RolloutContractTest(unittest.TestCase):
    def test_rendered_rollout_contract(self):
        for replicas in (1, 2, 3):
            with self.subTest(replicas=replicas):
                output = subprocess.check_output(
                    ["helm", "template", "test", str(CHART), "--set", f"replicaCount={replicas}"],
                    text=True,
                )
                deployments = [
                    document for document in yaml.safe_load_all(output)
                    if document and document.get("kind") == "Deployment"
                ]
                self.assertEqual(len(deployments), 1)
                spec = deployments[0]["spec"]
                self.assertEqual(spec["replicas"], replicas)
                self.assertEqual(spec["strategy"], {
                    "type": "RollingUpdate",
                    "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
                })
                self.assertEqual(spec["minReadySeconds"], 30)
                self.assertEqual(spec["progressDeadlineSeconds"], replicas * 330 + 300)
                pod = spec["template"]["spec"]
                self.assertEqual(pod["terminationGracePeriodSeconds"], 60)
                self.assertEqual(len(pod["containers"]), 1)
                manager = pod["containers"][0]
                for probe, path in (
                    ("startupProbe", "/healthz"),
                    ("livenessProbe", "/healthz"),
                    ("readinessProbe", "/readyz"),
                ):
                    self.assertEqual(manager[probe]["httpGet"], {"path": path, "port": "health"})
                startup = manager["startupProbe"]
                self.assertEqual(startup["periodSeconds"] * startup["failureThreshold"], 300)
                self.assertEqual(manager["lifecycle"]["preStop"], {"sleep": {"seconds": 5}})
                self.assertIn({"name": "health", "containerPort": 8081}, manager["ports"])

    def test_gpg_trust_root_rbac(self):
        output = subprocess.check_output(
            ["helm", "template", "test", str(CHART), "--namespace", "operator-system"],
            text=True,
        )
        documents = [doc for doc in yaml.safe_load_all(output) if doc]
        roles = {doc["metadata"]["name"]: doc for doc in documents if doc["kind"] == "ClusterRole"}
        state_roles = []
        for name, role in roles.items():
            self.assertFalse(any(label.startswith("rbac.authorization.k8s.io/aggregate-to-")
                                 for label in role["metadata"].get("labels", {})))
            for rule in role["rules"]:
                if "forgejo.jakeschurch.com" in rule["apiGroups"]:
                    self.assertNotIn("*", rule["resources"])
                    if "forgejogpgkeystates" in rule["resources"]:
                        self.assertEqual(rule["resources"], ["forgejogpgkeystates"])
                        self.assertEqual(set(rule["verbs"]), {"get", "create", "update", "patch", "delete"})
                        state_roles.append(name)
        self.assertEqual(len(state_roles), 1)
        bindings = [doc for doc in documents if doc["kind"] == "ClusterRoleBinding"
                    and doc["roleRef"]["name"] == state_roles[0]]
        self.assertEqual(len(bindings), 1)
        accounts = [doc for doc in documents if doc["kind"] == "ServiceAccount"]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(bindings[0]["subjects"], [{
            "kind": "ServiceAccount", "name": accounts[0]["metadata"]["name"], "namespace": "operator-system",
        }])
        state_crd = yaml.safe_load((CHART / "crds/forgejo.jakeschurch.com_forgejogpgkeystates.yaml").read_text())
        self.assertEqual(state_crd["spec"]["scope"], "Cluster")


if __name__ == "__main__":
    unittest.main()
