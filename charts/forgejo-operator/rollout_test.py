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


if __name__ == "__main__":
    unittest.main()
