from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

import vulndockyard.cli as cli
from vulndockyard.catalogue import ReviewedLab
from vulndockyard.errors import CancelledError
from vulndockyard.hosts import HostsManager, parse_managed_hosts
from vulndockyard.paths import Paths
from vulndockyard.runtime import RuntimeStatus, RuntimeUpdate
from vulndockyard.updates import UpdateCheck


def status(lab: ReviewedLab, state: str = "running") -> RuntimeStatus:
    return RuntimeStatus(
        lab.manifest.id,
        state,
        f"http://{lab.manifest.friendly_hostname}",
        "a" * 32 if state != "absent" else "",
        "registry.example.test/app@sha256:" + "b" * 64 if state != "absent" else "",
        "sha256:" + "b" * 64 if state != "absent" else "",
        lab.manifest.trust.value,
        state != "absent",
        state != "absent",
        (),
    )


class FakeRuntime:
    def __init__(self, catalogue: object = None) -> None:
        self.paths = Paths.discover()

    def pull(self, lab: ReviewedLab) -> tuple[str, ...]:
        return tuple(image.reference for image in lab.manifest.images)

    def up(self, lab: ReviewedLab, **values: Any) -> RuntimeStatus:
        return status(lab)

    def status(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab, "absent")

    def stop(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab, "stopped")

    def restart(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab)

    def rebuild(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab)

    def reset(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab)

    def remove(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab, "absent")

    def purge(self, lab: ReviewedLab, *, images: bool) -> RuntimeStatus:
        return status(lab, "absent")

    def logs(self, lab: ReviewedLab, *, follow: bool) -> str:
        return "bounded logs\n"

    def open(self, lab: ReviewedLab) -> str:
        return f"http://{lab.manifest.friendly_hostname}"

    def verify(self, lab: ReviewedLab) -> RuntimeStatus:
        return status(lab)

    def activate_reviewed_update(self, lab: ReviewedLab) -> RuntimeUpdate:
        current = status(lab)
        return RuntimeUpdate(
            lab.manifest.id,
            "already-current",
            lab.manifest_identity,
            lab.manifest_identity,
            current.run_id,
            current.run_id,
            current,
        )


@pytest.fixture
def isolated_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> type[FakeRuntime]:
    for name in ("CACHE", "STATE", "CONFIG", "DATA"):
        monkeypatch.setenv(f"XDG_{name}_HOME", str(tmp_path / name.casefold()))
    monkeypatch.setattr(cli, "Runtime", FakeRuntime)
    return FakeRuntime


@pytest.mark.parametrize(
    "arguments",
    [
        ["version"],
        ["list"],
        ["search", "graphql"],
        ["info", "juice-shop"],
        ["--ground-truth", "info", "juice-shop"],
        ["trust", "juice-shop"],
        ["pull", "juice-shop"],
        ["up", "juice-shop", "--port", "18080"],
        ["start", "juice-shop", "--port", "18080"],
        ["status"],
        ["status", "juice-shop"],
        ["logs", "juice-shop"],
        ["down", "juice-shop"],
        ["stop", "juice-shop"],
        ["restart", "juice-shop"],
        ["rebuild", "juice-shop"],
        ["reset", "juice-shop", "--yes"],
        ["remove", "juice-shop", "--yes"],
        ["purge", "juice-shop", "--images", "--yes"],
        ["open", "juice-shop"],
        ["verify", "juice-shop"],
        ["completion", "bash"],
        ["completion", "zsh"],
        ["completion", "fish"],
    ],
)
def test_public_commands_have_successful_dispatch(
    arguments: list[str], isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(arguments) == 0
    assert capsys.readouterr().out


def test_help_and_every_topic_are_available(capsys: pytest.CaptureFixture[str]) -> None:
    parser = cli.build_parser()
    for topic in parser._vdy_choices:
        assert cli.main(["help", topic]) == 0
        assert "usage:" in capsys.readouterr().out
    assert cli.main(["help"]) == 0
    assert "A provenance-aware" in capsys.readouterr().out


@pytest.mark.parametrize(
    "arguments",
    (["help"], ["help", "up"], ["version"], ["completion", "bash"]),
)
def test_metadata_commands_do_not_construct_catalogue_or_runtime(
    arguments: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("metadata command constructed runtime state")

    monkeypatch.setattr(cli, "Catalogue", unexpected)
    monkeypatch.setattr(cli, "Runtime", unexpected)
    monkeypatch.setenv("VDY_TIMEOUT_INSPECT", "invalid")

    assert cli.main(arguments) == 0
    assert capsys.readouterr().out


def test_json_contract_is_stable_and_deterministic(
    isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["list", "--json"]) == 0
    first = capsys.readouterr().out
    assert cli.main(["--json", "list"]) == 0
    second = capsys.readouterr().out
    assert first == second
    document = json.loads(first)
    assert document["schema_version"] == 1
    assert document["command"] == "list"
    assert [item["id"] for item in document["data"]] == sorted(
        item["id"] for item in document["data"]
    )
    assert cli.main(["help", "status", "--json"]) == 0
    help_document = json.loads(capsys.readouterr().out)
    assert help_document["command"] == "help"
    assert help_document["data"]["topic"] == "status"


def test_json_destructive_command_is_one_document(
    isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["reset", "juice-shop", "--yes", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["command"] == "reset"
    assert document["data"]["preview"]["lab_id"] == "juice-shop"
    assert document["data"]["preview"]["effects"] == [
        "owned containers and networks",
        "all eight owned ephemeral data volumes",
        "server-side accounts, progress, uploads, logs, and generated state",
    ]
    assert document["data"]["preview"]["owned_volume_names"] == [
        "data",
        "ftp",
        "frontend",
        "csaf",
        "i18n",
        "logs",
        "uploads-complaints",
        "tmp",
    ]
    assert document["data"]["preview"]["persistent_data_deleted"] is False
    assert document["data"]["status"]["lock_match"] is True


@pytest.mark.parametrize("command", ["remove", "purge"])
def test_runtime_removal_preview_names_every_owned_resource_kind(
    command: str,
    isolated_cli: type[FakeRuntime],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--json", command, "juice-shop", "--yes"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["data"]["preview"]["effects"] == [
        "owned containers",
        "owned networks",
        "owned volumes",
        "generated state",
    ]


def test_stable_error_codes_and_json_errors(
    isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["does-not-exist"]) == 2
    assert "Error:" in capsys.readouterr().err
    assert cli.main(["--json", "info", "does-not-exist"]) == 3
    error = json.loads(capsys.readouterr().err)
    assert error["schema_version"] == 1
    assert error["error"]["code"] == 3
    assert cli.main(["up", "bwapp"]) == 0  # fake dispatcher proves parsing only


def test_unexpected_error_has_stable_non_disclosing_json(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        FakeRuntime,
        "pull",
        lambda self, lab: (_ for _ in ()).throw(OSError("/private/operator/path")),
    )
    assert cli.main(["--json", "pull", "juice-shop"]) == 6
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["code"] == 6
    assert error["error"]["message"] == "unexpected controller failure (OSError)"


def test_hosts_helper_metadata_does_not_elevate(
    isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["--json", "hosts", "helper"]) == 0
    value = json.loads(capsys.readouterr().out)["data"]
    assert value["sha256"] == cli.HELPER_SHA256
    assert value["install_paths"] == [
        "/usr/local/libexec/vulndockyard-hosts",
        "/usr/libexec/vulndockyard-hosts",
    ]


def test_destructive_command_requires_confirmation_noninteractively(
    isolated_cli: type[FakeRuntime], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["reset", "juice-shop"]) == 8
    captured = capsys.readouterr()
    assert "Will remove" in captured.out
    assert "confirmation required" in captured.err


def test_update_check_and_noop_apply(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda lab: UpdateCheck(lab.manifest.id, "v20.2.0", "v20.2.0", False),
    )
    assert cli.main(["update", "--check", "juice-shop"]) == 0
    assert "current" in capsys.readouterr().out
    assert cli.main(["update", "juice-shop"]) == 0
    assert "already-current" in capsys.readouterr().out


def test_update_refuses_discovery_without_an_installed_reviewed_candidate(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "check_latest",
        lambda lab: UpdateCheck(lab.manifest.id, "v20.2.0", "v20.3.0", True),
    )
    assert cli.main(["update", "juice-shop"]) == 4
    assert "no reviewed immutable lock" in capsys.readouterr().err


class FixtureHostsManager(HostsManager):
    fixture_path: Path

    def __init__(self) -> None:
        super().__init__(self.fixture_path)


def test_hosts_commands_are_idempotent_on_fixture(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n# unrelated\n"
    path.write_bytes(original)
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["hosts", "add", "juice-shop", "--yes"]) == 0
    first = path.read_bytes()
    assert cli.main(["hosts", "add", "juice-shop", "--yes"]) == 0
    assert path.read_bytes() == first
    assert cli.main(["hosts", "remove", "juice-shop", "--yes"]) == 0
    assert path.read_bytes() == original
    assert capsys.readouterr().out


def test_json_hosts_without_yes_is_an_exact_non_mutating_preview(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n# unrelated\n"
    path.write_bytes(original)
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)

    assert cli.main(["--json", "hosts", "add", "juice-shop"]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["data"]["applied"] is False
    assert document["data"]["changed"] is True
    assert document["data"]["before_block"] == ""
    assert "127.0.0.1\tjuice-shop.test" in document["data"]["after_block"]
    assert path.read_bytes() == original


def test_interactive_hosts_confirmation_shows_exact_managed_block(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    assert cli.main(["hosts", "add", "juice-shop"]) == 0

    output = capsys.readouterr().out
    assert "Proposed VulnDockyard hosts modification:" in output
    assert "# BEGIN VULNDOCKYARD MANAGED BLOCK" in output
    assert "127.0.0.1\tjuice-shop.test" in output


class FakeProvider:
    def __init__(self, paths: Paths) -> None:
        pass

    def sync(self) -> tuple[object, ...]:
        return ()

    def status(self) -> dict[str, object]:
        return {"provider": "vulhub", "state": "verified", "entries": 0}

    def search(self, query: str) -> tuple[object, ...]:
        return ()


def test_provider_dispatch(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "VulhubProvider", FakeProvider)
    assert cli.main(["provider", "status", "vulhub"]) == 0
    assert "verified" in capsys.readouterr().out
    assert cli.main(["provider", "sync", "vulhub"]) == 0
    assert "entries: 0" in capsys.readouterr().out
    assert cli.main(["search", "CVE", "--provider", "vulhub"]) == 0
    assert "No matches" in capsys.readouterr().out


class DoctorDocker:
    def preflight(self) -> dict[str, object]:
        return {
            "engine": "28.1.1",
            "engine_version": {"major": 28, "minor": 1, "patch": 1, "suffix": ""},
            "minimum_engine": "28.0.0",
            "isolated_networking": True,
            "compose_v2": True,
        }


def test_doctor_success_and_repair_flag_parse(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\n")
    hosts.chmod(0o644)
    FixtureHostsManager.fixture_path = hosts
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(cli, "Docker", DoctorDocker)
    monkeypatch.setattr(cli, "port_available", lambda port: True)
    assert cli.main(["doctor"]) == 0
    captured = capsys.readouterr()
    assert "PASS docker-engine" in captured.out
    assert "PASS docker-engine-isolation" in captured.out
    assert "isolated IPv4 bridge gateway mode" in captured.out


def test_doctor_advisory_failures_do_not_fail(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class NoComposeDocker:
        def preflight(self) -> dict[str, object]:
            return {
                "engine": "28.1.1",
                "engine_version": {"major": 28, "minor": 1, "patch": 1, "suffix": ""},
                "minimum_engine": "28.0.0",
                "isolated_networking": True,
                "compose_v2": False,
            }

    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\n")
    hosts.chmod(0o644)
    FixtureHostsManager.fixture_path = hosts
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(cli, "Docker", NoComposeDocker)
    monkeypatch.setattr(cli, "port_available", lambda port: False)
    assert cli.main(["doctor"]) == 0
    captured = capsys.readouterr()
    assert "WARN docker-compose-v2" in captured.out
    assert "WARN loopback-port-80" in captured.out


def test_doctor_fails_when_engine_cannot_enforce_isolated_gateway_mode(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class OldDocker:
        def preflight(self) -> dict[str, object]:
            return {
                "engine": "27.5.1",
                "engine_version": {"major": 27, "minor": 5, "patch": 1, "suffix": ""},
                "minimum_engine": "28.0.0",
                "isolated_networking": False,
                "compose_v2": True,
            }

    monkeypatch.setattr(cli, "Docker", OldDocker)
    monkeypatch.setattr(cli, "port_available", lambda port: True)
    assert cli.main(["doctor"]) == 5
    captured = capsys.readouterr()
    assert "FAIL docker-engine-isolation" in captured.err
    assert "prevent the internal application network" in captured.err
    assert "Linux Mint" in captured.err
    assert "upgrade manually" in captured.err
    assert "never installs or modifies Docker" in captured.err


def test_doctor_reports_docker_permission_failure_without_disclosing_path(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class InaccessibleDocker:
        def preflight(self) -> dict[str, object]:
            raise PermissionError("/private/operator/docker.sock")

    monkeypatch.setattr(cli, "Docker", InaccessibleDocker)
    monkeypatch.setattr(cli, "port_available", lambda port: True)
    assert cli.main(["doctor"]) == 5
    captured = capsys.readouterr()
    assert "FAIL docker-engine" in captured.err
    assert "Docker access failed (PermissionError)" in captured.err
    assert "/private/operator" not in captured.err


def test_doctor_repairs_only_stale_managed_hosts(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n# unrelated\n"
    path.write_bytes(original)
    path.chmod(0o644)
    manager = HostsManager(path)
    manager.apply("juice-shop.test", add=True)
    manager.apply("removed-lab.test", add=True)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(cli, "Docker", DoctorDocker)
    monkeypatch.setattr(cli, "port_available", lambda port: True)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["doctor", "--repair-hosts", "--yes"]) == 0
    assert manager.preview("juice-shop.test", add=True).before == ("juice-shop.test",)
    assert b"# unrelated\n" in path.read_bytes()
    assert "PASS managed-hosts" in capsys.readouterr().out


def test_direct_confirmation_interactive_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    cli._confirm("continue", yes=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    with pytest.raises(CancelledError, match="cancelled"):
        cli._confirm("continue", yes=False)


def test_optional_hosts_offer_decline_is_non_destructive(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    path.write_bytes(original)
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")

    assert cli.main(["up", "juice-shop", "--port", "18080"]) == 0
    assert path.read_bytes() == original
    captured = capsys.readouterr()
    assert "Add it now?" not in captured.out  # input() prompts are replaced by the fixture.
    assert "Skipped. Add it later" in captured.out


@pytest.mark.parametrize("interruption", [EOFError(), KeyboardInterrupt()])
def test_optional_hosts_prompt_interruption_keeps_successful_start(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    interruption: BaseException,
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    path.write_bytes(original)
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    def interrupted(prompt: str) -> str:
        raise interruption

    monkeypatch.setattr("builtins.input", interrupted)
    assert cli.main(["up", "juice-shop", "--port", "18080"]) == 0
    assert path.read_bytes() == original
    assert "Skipped. Add it later" in capsys.readouterr().out


def test_optional_hosts_offer_accepts_and_applies_exact_entry(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n# unrelated\n"
    path.write_bytes(original)
    path.chmod(0o644)
    FixtureHostsManager.fixture_path = path
    monkeypatch.setattr(cli, "HostsManager", FixtureHostsManager)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    assert cli.main(["up", "juice-shop", "--port", "18080"]) == 0
    assert parse_managed_hosts(path.read_bytes()) == ("juice-shop.test",)
    assert b"# unrelated\n" in path.read_bytes()
    assert "Friendly hostname juice-shop.test: added" in capsys.readouterr().out


def test_optional_hosts_offer_cannot_turn_a_successful_start_into_failure(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class UnreadableHosts:
        def preview(self, hostname: str, *, add: bool) -> object:
            raise OSError("synthetic unreadable hosts")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cli, "HostsManager", UnreadableHosts)
    assert cli.main(["up", "juice-shop", "--port", "18080"]) == 0
    captured = capsys.readouterr()
    assert "juice-shop: running" in captured.out
    assert "could not inspect optional hosts entry" in captured.err


def test_main_catches_interrupt_and_domain_error(
    isolated_cli: type[FakeRuntime],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        FakeRuntime, "up", lambda self, lab, **values: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    assert cli.main(["up", "juice-shop"]) == 8
    assert "interrupted" in capsys.readouterr().err
