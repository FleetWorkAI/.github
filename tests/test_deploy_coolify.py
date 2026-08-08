import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.deploy_coolify import (
    GateError,
    Service,
    Target,
    assert_no_duplicate_env,
    deploy_target,
    load_service,
    preflight_target,
    restart_marker,
    run,
    validate_sha,
    verify_github,
    verify_prerequisites,
)


SHA = "a" * 40


class FakeClient:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, path, accept="application/json"):
        self.calls.append(("GET", path))
        value = self.routes.get(("GET", path))
        if isinstance(value, tuple):
            if not value:
                raise AssertionError(f"no fake response left for {path}")
            self.routes[("GET", path)] = value[1:]
            return value[0]
        if value is None:
            raise AssertionError(f"unexpected GET {path}")
        return value

    def patch(self, path, payload):
        self.calls.append(("PATCH", path, payload))
        value = self.routes.get(("PATCH", path))
        return {} if value is None else value


def service():
    return Service(
        name="runner",
        repository="FleetWorkAI/agent-runner",
        required_checks=("cargo test", "Security"),
        targets=(Target("agent-runner", "runner-uuid", "starting runner"),),
    )


def check(name, conclusion="success", run_id=1):
    return {
        "id": run_id,
        "name": name,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"slug": "github-actions"},
    }


def deux_services(requires=("amont",)):
    """Un aval qui exige un amont, et l'amont lui-meme."""
    return {
        "schemaVersion": 1,
        "services": {
            "amont": {
                "repository": "FleetWorkAI/agent-runner",
                "requiredChecks": ["CI"],
                "targets": [{"name": "amont-app", "uuid": "amont-uuid", "bootMarker": "ready"}],
            },
            "aval": {
                "repository": "FleetWorkAI/agent-coordinator",
                "requiredChecks": ["CI"],
                "targets": [{"name": "aval-app", "uuid": "aval-uuid", "bootMarker": "ready"}],
                "requires": list(requires),
            },
        },
    }


class PrerequisiteTests(unittest.TestCase):
    """L'ordre de deploiement, impose par le script et non par un plan.

    Deployer le coordinateur avant le runner ne perd pas un champ : la fonction
    SQL rend `false` et `admit_run` refuse 100 % des admissions. Jusqu'ici cet
    ordre n'existait que dans un document, et le script prend `--service`, un
    seul a la fois : se tromper etait un clic.
    """

    def _config(self, contenu):
        directory = tempfile.mkdtemp()
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(contenu))
        return path

    def test_prerequisite_a_jour_laisse_passer(self):
        # Contrôle POSITIF. Sans lui, un refus systematique passerait le test
        # negatif ci-dessous tout en bloquant tous les deploiements.
        path = self._config(deux_services())
        aval = load_service(path, "aval")
        github = FakeClient({("GET", "/repos/FleetWorkAI/agent-runner/commits/main"): {"sha": SHA}})
        coolify = FakeClient({("GET", "/applications/amont-uuid"): {"git_commit_sha": SHA}})
        verify_prerequisites(path, coolify, github, aval)

    def test_prerequisite_en_retard_est_refuse(self):
        path = self._config(deux_services())
        aval = load_service(path, "aval")
        github = FakeClient({("GET", "/repos/FleetWorkAI/agent-runner/commits/main"): {"sha": SHA}})
        coolify = FakeClient({("GET", "/applications/amont-uuid"): {"git_commit_sha": "b" * 40}})
        with self.assertRaisesRegex(GateError, "prerequisite amont is behind"):
            verify_prerequisites(path, coolify, github, aval)

    def test_message_de_refus_dit_quoi_faire(self):
        # Une porte qui refuse sans dire dans quel sens aller se contourne.
        path = self._config(deux_services())
        aval = load_service(path, "aval")
        github = FakeClient({("GET", "/repos/FleetWorkAI/agent-runner/commits/main"): {"sha": SHA}})
        coolify = FakeClient({("GET", "/applications/amont-uuid"): {"git_commit_sha": ""}})
        with self.assertRaises(GateError) as capture:
            verify_prerequisites(path, coolify, github, aval)
        message = str(capture.exception)
        self.assertIn("Deploy amont first", message)
        self.assertIn("refuse every run", message)

    def test_sans_prerequis_aucun_appel_reseau(self):
        path = self._config(deux_services(requires=()))
        aval = load_service(path, "aval")
        github, coolify = FakeClient(), FakeClient()
        verify_prerequisites(path, coolify, github, aval)
        self.assertEqual(github.calls, [])
        self.assertEqual(coolify.calls, [])

    def test_prerequis_inconnu_est_refuse_au_chargement(self):
        path = self._config(deux_services(requires=("fantome",)))
        with self.assertRaisesRegex(GateError, "unknown prerequisite"):
            load_service(path, "aval")

    def test_un_service_ne_peut_pas_s_exiger_lui_meme(self):
        path = self._config(deux_services(requires=("aval",)))
        with self.assertRaisesRegex(GateError, "cannot require itself"):
            load_service(path, "aval")

    def _run_avec(self, sha_amont_deploye, dry_run):
        """Joue `run()` de bout en bout, avec les deux clients simules."""
        path = self._config(deux_services())
        aval_repo = "/repos/FleetWorkAI/agent-coordinator"
        github = FakeClient(
            {
                ("GET", f"{aval_repo}/commits/main"): {"sha": SHA},
                ("GET", f"{aval_repo}/commits/{SHA}/check-runs?filter=latest&per_page=100"): {
                    "total_count": 1,
                    "check_runs": [check("CI")],
                },
                ("GET", "/repos/FleetWorkAI/agent-runner/commits/main"): {"sha": SHA},
            }
        )
        coolify = FakeClient(
            {
                ("GET", "/applications/amont-uuid"): {"git_commit_sha": sha_amont_deploye},
                ("GET", "/applications/aval-uuid"): {
                    "name": "aval-app",
                    "git_repository": "FleetWorkAI/agent-coordinator",
                    "git_branch": "main",
                },
                ("GET", "/applications/aval-uuid/envs"): [],
            }
        )
        args = argparse.Namespace(
            config=path,
            service="aval",
            sha=SHA,
            dry_run=dry_run,
            timeout_seconds=1,
            poll_seconds=0,
        )
        environnement = {
            "FLEETWORK_GITHUB_READ_TOKEN": "jeton",
            "COOLIFY_URL": "https://coolify.test",
            "COOLIFY_API_TOKEN": "jeton",
        }
        with patch.dict(os.environ, environnement, clear=False):
            with patch("scripts.deploy_coolify.JsonClient", side_effect=[github, coolify]):
                return run(args)

    def test_la_porte_est_branchee_sur_run(self):
        # Une garde testee mais jamais appelee est une garde absente. Ce test
        # passe par `run()`, donc il tombe si quelqu'un retire l'appel.
        with self.assertRaisesRegex(GateError, "prerequisite amont is behind"):
            self._run_avec("b" * 40, dry_run=True)

    def test_le_vol_a_blanc_ne_valide_pas_un_ordre_faux(self):
        # Un « validated » rendu sur un ordre inverse serait un feu vert pour la
        # panne : c'est justement le mode qu'on utilise pour se rassurer.
        resultat = self._run_avec(SHA, dry_run=True)
        self.assertEqual(resultat["status"], "validated")

    def test_la_configuration_livree_declare_la_chaine_reelle(self):
        # Le fichier de production, pas une maquette : c'est lui qui protege.
        reel = Path(__file__).resolve().parents[1] / "config" / "coolify-services.json"
        self.assertEqual(load_service(reel, "agent-runner").requires, ())
        self.assertEqual(load_service(reel, "agent-coordinator").requires, ("agent-runner",))
        self.assertEqual(load_service(reel, "web-worker").requires, ("agent-coordinator",))


class ConfigTests(unittest.TestCase):
    def test_sha_requires_full_commit(self):
        with self.assertRaisesRegex(GateError, "40-character"):
            validate_sha("abc123")

    def test_unknown_service_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"schemaVersion": 1, "services": {}}))
            with self.assertRaisesRegex(GateError, "not allowlisted"):
                load_service(path, "unknown")

    def test_duplicate_target_uuid_is_refused(self):
        config = {
            "schemaVersion": 1,
            "services": {
                "x": {
                    "repository": "FleetWorkAI/x",
                    "requiredChecks": ["CI"],
                    "targets": [
                        {"name": "a", "uuid": "same", "bootMarker": "ready"},
                        {"name": "b", "uuid": "same", "bootMarker": "ready"},
                    ],
                }
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(GateError, "more than once"):
                load_service(path, "x")


class GithubGateTests(unittest.TestCase):
    def github(self, checks, main_sha=SHA, total_count=None):
        repo = "/repos/FleetWorkAI/agent-runner"
        return FakeClient(
            {
                ("GET", f"{repo}/commits/main"): {"sha": main_sha},
                ("GET", f"{repo}/commits/{SHA}/check-runs?filter=latest&per_page=100"): {
                    "total_count": len(checks) if total_count is None else total_count,
                    "check_runs": checks,
                },
            }
        )

    def test_current_main_with_green_checks_passes(self):
        verify_github(self.github([check("cargo test"), check("Security")]), service(), SHA)

    def test_sha_other_than_main_is_refused(self):
        with self.assertRaisesRegex(GateError, "not the current main"):
            verify_github(self.github([], main_sha="b" * 40), service(), SHA)

    def test_missing_or_failed_check_is_refused(self):
        with self.assertRaisesRegex(GateError, "cargo test: completed/failure, Security: missing"):
            verify_github(self.github([check("cargo test", "failure")]), service(), SHA)

    def test_latest_rerun_is_authoritative(self):
        runs = [check("cargo test", "failure", 1), check("cargo test", "success", 2), check("Security")]
        verify_github(self.github(runs), service(), SHA)

    def test_incomplete_check_page_is_refused(self):
        with self.assertRaisesRegex(GateError, "incomplete evaluation"):
            verify_github(self.github([check("cargo test")], total_count=101), service(), SHA)


class CoolifyGateTests(unittest.TestCase):
    def test_duplicate_environment_keys_are_refused_without_values(self):
        client = FakeClient({("GET", "/applications/runner-uuid/envs"): [
            {"key": "TOKEN", "value": "first", "is_preview": False},
            {"key": "TOKEN", "value": "second", "is_preview": False},
        ]})
        with self.assertRaisesRegex(GateError, r"TOKEN\[production\]"):
            assert_no_duplicate_env(client, service().targets[0])

    def test_production_and_preview_rows_are_distinct_scopes(self):
        client = FakeClient({("GET", "/applications/runner-uuid/envs"): [
            {"key": "TOKEN", "value": "production", "is_preview": False},
            {"key": "TOKEN", "value": "preview", "is_preview": True},
        ]})
        assert_no_duplicate_env(client, service().targets[0])

    def test_preflight_refuses_a_repository_mismatch_without_mutation(self):
        client = FakeClient({("GET", "/applications/runner-uuid"): {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/wrong",
            "git_branch": "main",
        }})
        with self.assertRaisesRegex(GateError, "repository mismatch"):
            preflight_target(client, service(), service().targets[0])
        self.assertFalse(any(call[0] == "PATCH" for call in client.calls))

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_deploy_pins_sha_and_proves_fresh_boot(self, _sleep):
        # Forme réelle de l'API LanaCool : `last_restart_at` reste null, c'est
        # `last_online_at` qui avance. L'ancienne version de ce test renseignait
        # `last_restart_at`, donc elle validait le code contre une fiction.
        app_before = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": "HEAD",
            "last_online_at": "2026-08-07 18:09:31",
            "last_restart_at": None,
            "status": "running:healthy",
        }
        app_after = {
            **app_before,
            "git_commit_sha": SHA,
            "last_online_at": "2026-08-07 18:56:56",
        }
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app_before, app_after, app_after),
                ("GET", "/applications/runner-uuid/envs"): [{"key": "ONE"}],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": SHA},
                ("GET", "/applications/runner-uuid/logs?lines=200"): {
                    "logs": "starting runner"
                },
            }
        )
        deploy_id = deploy_target(client, service(), service().targets[0], SHA, 1, 0)
        self.assertEqual(deploy_id, "dep-1")
        self.assertIn(("PATCH", "/applications/runner-uuid", {"git_commit_sha": SHA}), client.calls)

    def test_restart_marker_names_the_field_it_read(self):
        self.assertEqual(
            restart_marker({"last_online_at": "2026-08-07 18:56:56"}),
            ("last_online_at", "2026-08-07 18:56:56"),
        )
        self.assertEqual(
            restart_marker({"last_online_at": None, "last_restart_at": "x"}),
            ("last_restart_at", "x"),
        )
        self.assertIsNone(restart_marker({"last_online_at": None, "last_restart_at": None}))
        self.assertIsNone(restart_marker({"last_online_at": "   "}))

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_deployment_without_any_restart_timestamp_is_refused(self, _sleep):
        # Le cas réel du 2026-08-07 : Coolify laisse les deux champs à null.
        # La porte doit refuser plutôt que de croire le conteneur redémarré.
        app_before = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": "HEAD",
            "last_online_at": None,
            "last_restart_at": None,
            "status": "running:healthy",
        }
        app_after = {**app_before, "git_commit_sha": SHA}
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app_before, app_after, app_after),
                ("GET", "/applications/runner-uuid/envs"): [{"key": "ONE"}],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": SHA},
            }
        )
        with self.assertRaisesRegex(GateError, "exposes no restart timestamp"):
            deploy_target(client, service(), service().targets[0], SHA, 1, 0)

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_unchanged_restart_timestamp_is_refused(self, _sleep):
        # Le conteneur n'a pas redémarré : même horodatage avant et après.
        app = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": SHA,
            "last_online_at": "2026-08-07 18:09:31",
            "status": "running:healthy",
        }
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app, app, app),
                ("GET", "/applications/runner-uuid/envs"): [{"key": "ONE"}],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": SHA},
            }
        )
        with self.assertRaisesRegex(GateError, "no fresh restart marker"):
            deploy_target(client, service(), service().targets[0], SHA, 1, 0)

    @patch("scripts.deploy_coolify.time.sleep", return_value=None)
    def test_deployment_commit_mismatch_is_refused(self, _sleep):
        app = {
            "name": "agent-runner",
            "git_repository": "FleetWorkAI/agent-runner",
            "git_branch": "main",
            "git_commit_sha": SHA,
            "last_online_at": "2026-08-07 18:09:31",
            "status": "running:healthy",
        }
        client = FakeClient(
            {
                ("GET", "/applications/runner-uuid"): (app, app),
                ("GET", "/applications/runner-uuid/envs"): [],
                ("GET", "/deploy?uuid=runner-uuid&force=false"): {"deployment_uuid": "dep-1"},
                ("GET", "/deployments/dep-1"): {"status": "finished", "commit": "b" * 40},
            }
        )
        with self.assertRaisesRegex(GateError, "did not prove commit"):
            deploy_target(client, service(), service().targets[0], SHA, 1, 0)


if __name__ == "__main__":
    unittest.main()
