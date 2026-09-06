"""VulnDockyard command-line interface."""

from __future__ import annotations

import argparse
import dataclasses
import os
import platform
import shutil
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Never

from . import __version__
from .catalogue import Catalogue, ReviewedLab
from .docker import Docker
from .errors import CancelledError, ExitCode, PreflightError, VulnDockyardError
from .hosts import HostsManager, parse_managed_hosts
from .output import Output
from .paths import Paths
from .process import Runner
from .provider import VulhubProvider
from .runtime import Runtime, RuntimeStatus, port_available
from .updates import apply_reviewed_update, check_latest

DESCRIPTION = "A provenance-aware local runner for intentionally vulnerable security labs."


class Parser(argparse.ArgumentParser):
    _vdy_choices: Mapping[str, argparse.ArgumentParser]

    def error(self, message: str) -> Never:
        raise argparse.ArgumentError(None, message)


def _lab_argument(parser: argparse.ArgumentParser, *, optional: bool = False) -> None:
    parser.add_argument(
        "lab", nargs="?" if optional else None, help="stable lab ID or unambiguous name"
    )


def build_parser() -> Parser:
    parser = Parser(prog="vulndockyard", description=DESCRIPTION)
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON contract v1")
    parser.add_argument(
        "--ground-truth",
        action="store_true",
        help="include opt-in non-solution verification metadata",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    commands.add_parser("help", help="show command help").add_argument(
        "topic", nargs="?", help="command name"
    )
    commands.add_parser("version", help="show the controller version")
    doctor = commands.add_parser("doctor", help="check local safety and runtime prerequisites")
    doctor.add_argument(
        "--repair-hosts", action="store_true", help="remove stale managed hosts entries"
    )
    doctor.add_argument("--yes", action="store_true", help="confirm the proposed repair")
    commands.add_parser("list", help="list the reviewed initial catalogue")
    search = commands.add_parser("search", help="search labs and optional provider index")
    search.add_argument("query")
    search.add_argument("--provider", choices=("vulhub",), help="search a synced provider index")
    for name, help_text in (
        ("info", "show adapter details"),
        ("trust", "show image trust evidence"),
        ("pull", "pull reviewed digest-pinned images"),
        ("open", "open the running lab URL"),
        ("verify", "verify readiness, identity, and lock match"),
    ):
        child = commands.add_parser(name, help=help_text)
        _lab_argument(child)
    up = commands.add_parser("up", aliases=["start"], help="start a reviewed lab")
    _lab_argument(up)
    up.add_argument(
        "--port", type=int, default=80, help="explicit loopback gateway port (default: 80)"
    )
    up.add_argument(
        "--allow-multiple", action="store_true", help="allow concurrent isolated lab projects"
    )
    up.add_argument(
        "--acknowledge-egress",
        action="store_true",
        help="acknowledge declared outbound Internet access",
    )
    up.add_argument(
        "--unsafe-development", action="store_true", help="mark a development run untrusted"
    )
    up.add_argument(
        "--unsafe-image", metavar="NAME@SHA256", help="immutable untrusted development app image"
    )
    status = commands.add_parser("status", help="show managed runtime state")
    _lab_argument(status, optional=True)
    logs = commands.add_parser("logs", help="show bounded application logs")
    _lab_argument(logs)
    logs.add_argument("--follow", action="store_true", help="follow for at most five minutes")
    for name, help_text in (
        ("down", "stop the lab without deleting it"),
        ("stop", "stop the lab without deleting it"),
        ("restart", "stop and start the same locked lab"),
    ):
        child = commands.add_parser(name, help=help_text)
        _lab_argument(child)
    rebuild = commands.add_parser(
        "rebuild", help="recreate with the same lock while preserving declared data"
    )
    _lab_argument(rebuild)
    reset = commands.add_parser(
        "reset", help="return a lab and owned data to its declared clean state"
    )
    _lab_argument(reset)
    reset.add_argument("--yes", action="store_true", help="confirm destructive effects")
    remove = commands.add_parser("remove", help="remove runtime resources but retain pulled images")
    _lab_argument(remove)
    remove.add_argument("--yes", action="store_true", help="confirm runtime removal")
    purge = commands.add_parser(
        "purge", help="remove only attributable lab resources and generated state"
    )
    _lab_argument(purge)
    purge.add_argument(
        "--images", action="store_true", help="also remove exact known image digests"
    )
    purge.add_argument("--yes", action="store_true", help="confirm destructive effects")
    update = commands.add_parser("update", help="discover or apply a reviewed transactional update")
    update.add_argument("--check", action="store_true", help="read-only upstream release discovery")
    _lab_argument(update, optional=True)
    hosts = commands.add_parser("hosts", help="manage the exact VulnDockyard /etc/hosts block")
    host_commands = hosts.add_subparsers(dest="hosts_command", required=True)
    for name in ("add", "remove"):
        child = host_commands.add_parser(name, help=f"{name} managed .test hostname entries")
        _lab_argument(child, optional=True)
        child.add_argument(
            "--yes", action="store_true", help="confirm the exact proposed modification"
        )
    provider = commands.add_parser("provider", help="operate a pinned metadata provider")
    provider_commands = provider.add_subparsers(dest="provider_command", required=True)
    for name in ("sync", "status"):
        child = provider_commands.add_parser(name, help=f"{name} pinned provider metadata")
        child.add_argument("provider", choices=("vulhub",))
    completion = commands.add_parser("completion", help="emit shell completion source")
    completion.add_argument("shell", choices=("bash", "zsh", "fish"))
    parser._vdy_choices = commands.choices
    return parser


def _lab_summary(lab: ReviewedLab) -> dict[str, object]:
    return {
        "id": lab.manifest.id,
        "name": lab.manifest.display_name,
        "status": lab.manifest.adapter_status.value,
        "trust": lab.manifest.trust.value,
        "hostname": lab.manifest.friendly_hostname,
        "reason": lab.manifest.status_reason,
    }


def _status_data(status: RuntimeStatus) -> dict[str, Any]:
    return dataclasses.asdict(status)


def _human_status(status: RuntimeStatus) -> str:
    if status.state == "absent":
        return f"{status.lab_id}: absent"
    lock = "matches lock" if status.lock_match else "does not match lock"
    trusted = "trusted" if status.trusted_run else "UNTRUSTED development run"
    return (
        f"{status.lab_id}: {status.state} ({trusted}; {lock})\n"
        f"URL: {status.url}\nRequested: {status.requested_reference}\n"
        f"Resolved: {status.resolved_digest}\nTrust: {status.trust_level}\nRun: {status.run_id}"
    )


def _confirm(message: str, *, yes: bool) -> None:
    if yes:
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CancelledError(
            f"confirmation required; review the preview and repeat with --yes: {message}"
        )
    answer = input(f"{message} [y/N] ").strip().casefold()
    if answer not in {"y", "yes"}:
        raise CancelledError("operation cancelled")


def _host_labs(catalogue: Catalogue, name: str | None) -> tuple[ReviewedLab, ...]:
    if name:
        return (catalogue.get(name),)
    return tuple(lab for lab in catalogue.all() if lab.manifest.adapter_status.value == "runnable")


def _apply_hosts(labs: tuple[ReviewedLab, ...], *, add: bool, yes: bool) -> dict[str, Any]:
    manager = HostsManager()
    hostnames = tuple(lab.manifest.friendly_hostname for lab in labs)
    return _apply_hostnames(manager, hostnames, add=add, yes=yes)


def _apply_hostnames(
    manager: HostsManager, hostnames: tuple[str, ...], *, add: bool, yes: bool
) -> dict[str, Any]:
    previews = [manager.preview(hostname, add=add) for hostname in hostnames]
    changed = [
        hostname for hostname, preview in zip(hostnames, previews, strict=True) if preview.changed
    ]
    action = "add" if add else "remove"
    if not changed:
        return {"action": action, "changed": False, "hostnames": hostnames}
    _confirm(f"{action} VulnDockyard hosts entries: {', '.join(changed)}", yes=yes)
    if os.geteuid() == 0:
        for hostname in changed:
            manager.apply(hostname, add=add)
    else:
        executable = shutil.which("sudo")
        if executable is None:
            raise PreflightError("sudo is required for the minimal /etc/hosts helper")
        runner = Runner()
        for hostname in changed:
            runner.run(
                (
                    executable,
                    "--",
                    sys.executable,
                    "-m",
                    "vulndockyard.hosts_helper",
                    action,
                    hostname,
                ),
                timeout=60,
            )
    final = parse_managed_hosts(manager.path.read_bytes())
    if add and not set(changed).issubset(final):
        raise PreflightError("managed hosts update could not be verified")
    if not add and set(changed) & set(final):
        raise PreflightError("managed hosts removal could not be verified")
    return {
        "action": action,
        "changed": True,
        "hostnames": tuple(changed),
        "managed_after": tuple(sorted(final)),
    }


def _doctor(paths: Paths) -> dict[str, Any]:
    checks: list[dict[str, object]] = []
    checks.append(
        {
            "name": "python",
            "ok": sys.version_info >= (3, 11),
            "required": True,
            "detail": platform.python_version(),
        }
    )
    docker = Docker()
    try:
        detail = docker.preflight()
        checks.append(
            {"name": "docker-engine", "ok": True, "required": True, "detail": detail["engine"]}
        )
        checks.append(
            {
                "name": "docker-compose-v2",
                "ok": bool(detail["compose_v2"]),
                "required": False,
                "detail": detail["compose_v2"],
            }
        )
    except VulnDockyardError as exc:
        checks.append({"name": "docker-engine", "ok": False, "required": True, "detail": str(exc)})
        checks.append(
            {
                "name": "docker-compose-v2",
                "ok": False,
                "required": False,
                "detail": "not checked",
            }
        )
    checks.append(
        {
            "name": "loopback-port-80",
            "ok": port_available(80),
            "required": False,
            "detail": "required by default; --port is explicit fallback",
        }
    )
    try:
        managed = parse_managed_hosts(Path("/etc/hosts").read_bytes())
        known = {lab.manifest.friendly_hostname for lab in Catalogue().all()}
        stale = tuple(sorted(set(managed) - known))
        checks.append(
            {
                "name": "managed-hosts",
                "ok": not stale,
                "required": True,
                "detail": {"managed": managed, "stale": stale},
            }
        )
    except (OSError, VulnDockyardError) as exc:
        checks.append({"name": "managed-hosts", "ok": False, "required": True, "detail": str(exc)})
    paths.ensure()
    checks.append(
        {
            "name": "xdg-paths",
            "ok": True,
            "required": True,
            "detail": "created with mode 0700",
        }
    )
    return {
        "ok": all(bool(check["ok"]) for check in checks if bool(check["required"])),
        "checks": checks,
    }


def _completion(shell: str) -> str:
    commands = (
        "help version doctor list search info trust pull up start open status logs reset rebuild "
        "restart down stop remove update verify hosts purge provider"
    )
    if shell == "bash":
        return f"complete -W '{commands}' vulndockyard vdy"
    if shell == "zsh":
        return f"compctl -k '({commands})' vulndockyard vdy"
    return f"complete -c vulndockyard -f -a '{commands}'; complete -c vdy -f -a '{commands}'"


def dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser, output: Output) -> None:
    command = str(args.command)
    catalogue = Catalogue()
    runtime = Runtime(catalogue=catalogue)
    if command == "help":
        if args.topic:
            choices = getattr(parser, "_vdy_choices", {})
            if not isinstance(choices, dict) or args.topic not in choices:
                raise argparse.ArgumentError(None, f"unknown help topic: {args.topic}")
            help_text = choices[args.topic].format_help()
        else:
            help_text = parser.format_help()
        output.emit(command, {"topic": args.topic, "text": help_text}, help_text.rstrip())
    elif command == "version":
        output.emit(command, {"version": __version__}, f"vulndockyard {__version__}")
    elif command == "doctor":
        result = _doctor(runtime.paths)
        stale_check = next(check for check in result["checks"] if check["name"] == "managed-hosts")
        stale_detail = stale_check["detail"]
        if args.repair_hosts and isinstance(stale_detail, dict) and stale_detail["stale"]:
            _apply_hostnames(HostsManager(), tuple(stale_detail["stale"]), add=False, yes=args.yes)
            result = _doctor(runtime.paths)
        human = "\n".join(
            f"{'PASS' if check['ok'] else ('FAIL' if check['required'] else 'WARN')} "
            f"{check['name']}: {check['detail']}"
            for check in result["checks"]
        )
        if not result["ok"]:
            raise PreflightError(f"one or more required doctor checks failed:\n{human}")
        output.emit(command, result, human)
    elif command == "list":
        list_values = [_lab_summary(lab) for lab in catalogue.all()]
        human = "\n".join(
            f"{item['id']:<20} {item['status']:<12} {item['trust']:<16} {item['name']}"
            for item in list_values
        )
        output.emit(command, list_values, human)
    elif command == "search":
        if args.provider == "vulhub":
            search_values = [
                dataclasses.asdict(entry)
                for entry in VulhubProvider(runtime.paths).search(args.query)
            ]
            human = (
                "\n".join(f"{item['status']:<8} {item['path']}" for item in search_values)
                or "No matches."
            )
        else:
            search_values = [_lab_summary(lab) for lab in catalogue.search(args.query)]
            human = (
                "\n".join(
                    f"{item['id']:<20} {item['status']:<12} {item['name']}"
                    for item in search_values
                )
                or "No matches."
            )
        output.emit(command, search_values, human)
    elif command in {"info", "trust"}:
        lab = catalogue.get(args.lab)
        if command == "trust":
            value = {
                "lab_id": lab.manifest.id,
                **lab.manifest.raw["trust"],
                "images": [dataclasses.asdict(image) for image in lab.manifest.images],
            }
            human = f"{lab.manifest.id}: {lab.manifest.trust.value}\n{lab.manifest.status_reason}"
        else:
            value = dict(lab.manifest.raw)
            if not args.ground_truth:
                value["verification"] = {
                    "status": value["verification"]["status"],
                    "spoilers": "omitted; use --ground-truth",
                }
            human = (
                f"{lab.manifest.display_name} ({lab.manifest.id})\n"
                f"Status: {lab.manifest.adapter_status.value}\n"
                f"Trust: {lab.manifest.trust.value}\n"
                f"URL: http://{lab.manifest.friendly_hostname}\n"
                f"{lab.manifest.description}\n{lab.manifest.status_reason}"
            )
        output.emit(command, value, human)
    elif command == "pull":
        lab = catalogue.get(args.lab)
        references = runtime.pull(lab)
        output.emit(
            command,
            {"lab_id": lab.manifest.id, "images": references},
            "\n".join(references),
        )
    elif command in {"up", "start"}:
        lab = catalogue.get(args.lab)
        status = runtime.up(
            lab,
            host_port=args.port,
            allow_multiple=args.allow_multiple,
            acknowledge_egress=args.acknowledge_egress,
            unsafe_image=args.unsafe_image,
            unsafe_development=args.unsafe_development,
        )
        output.emit("up", _status_data(status), _human_status(status))
        if sys.stdin.isatty() and not output.json_mode:
            manager = HostsManager()
            if lab.manifest.friendly_hostname not in parse_managed_hosts(manager.path.read_bytes()):
                print(f"Optional friendly name: vulndockyard hosts add {lab.manifest.id}")
    elif command == "status":
        labs = (catalogue.get(args.lab),) if args.lab else catalogue.all()
        statuses = [_status_data(runtime.status(lab)) for lab in labs]
        output.emit(
            command,
            statuses,
            "\n\n".join(_human_status(RuntimeStatus(**value)) for value in statuses),
        )
    elif command in {"down", "stop", "restart", "rebuild"}:
        lab = catalogue.get(args.lab)
        operation = runtime.stop if command in {"down", "stop"} else getattr(runtime, command)
        status = operation(lab)
        output.emit(command, _status_data(status), _human_status(status))
    elif command in {"reset", "remove", "purge"}:
        lab = catalogue.get(args.lab)
        effects = (
            lab.manifest.raw["reset"]["effects"]
            if command == "reset"
            else ["managed containers", "managed network", "generated state"]
        )
        if command == "purge" and args.images:
            effects = [*effects, "known immutable image digests"]
        preview = {"lab_id": lab.manifest.id, "effects": effects}
        effect_text = ", ".join(effects) if effects else "ephemeral runtime state"
        if not output.json_mode:
            print(f"Will remove: {effect_text}")
        _confirm(
            f"continue with {command} for {lab.manifest.id}; effects: {effect_text}",
            yes=args.yes,
        )
        status = (
            runtime.purge(lab, images=args.images)
            if command == "purge"
            else getattr(runtime, command)(lab)
        )
        output.emit(
            command,
            {"preview": preview, "status": _status_data(status)},
            _human_status(status),
        )
    elif command == "logs":
        lab = catalogue.get(args.lab)
        text = runtime.logs(lab, follow=args.follow)
        output.emit(command, {"lab_id": lab.manifest.id, "logs": text}, text.rstrip())
    elif command == "open":
        lab = catalogue.get(args.lab)
        url = runtime.open(lab)
        output.emit(command, {"lab_id": lab.manifest.id, "url": url}, url)
    elif command == "verify":
        lab = catalogue.get(args.lab)
        status = runtime.verify(lab)
        output.emit(
            command, _status_data(status), f"Verified: {status.url} ({status.resolved_digest})"
        )
    elif command == "update":
        labs = (
            (catalogue.get(args.lab),)
            if args.lab
            else tuple(
                lab for lab in catalogue.all() if lab.manifest.adapter_status.value == "runnable"
            )
        )
        checks = [check_latest(lab) for lab in labs]
        if args.check:
            output.emit(
                command,
                [dataclasses.asdict(value) for value in checks],
                "\n".join(
                    f"{value.lab_id}: {value.current} -> {value.available} "
                    f"({'available' if value.update_available else 'current'})"
                    for value in checks
                ),
            )
        else:
            results = [
                apply_reviewed_update(lab, check) for lab, check in zip(labs, checks, strict=True)
            ]
            output.emit(
                command,
                {"results": results},
                "\n".join(
                    f"{lab.manifest.id}: {result}"
                    for lab, result in zip(labs, results, strict=True)
                ),
            )
    elif command == "hosts":
        labs = _host_labs(catalogue, args.lab)
        host_value = _apply_hosts(labs, add=args.hosts_command == "add", yes=args.yes)
        hostnames = ", ".join(str(item) for item in host_value["hostnames"])
        outcome = "changed" if host_value["changed"] else "already correct"
        output.emit(
            command,
            host_value,
            f"Hosts {host_value['action']}: {hostnames} ({outcome})",
        )
    elif command == "provider":
        provider = VulhubProvider(runtime.paths)
        if args.provider_command == "sync":
            entries = provider.sync()
            provider_value = {
                "provider": "vulhub",
                "entries": len(entries),
                "runnable": sum(entry.status == "runnable" for entry in entries),
            }
        else:
            provider_value = provider.status()
        output.emit(
            command,
            provider_value,
            "\n".join(f"{key}: {item}" for key, item in provider_value.items()),
        )
    elif command == "completion":
        completion_source = _completion(args.shell)
        output.emit(
            command,
            {"shell": args.shell, "source": completion_source},
            completion_source,
        )
    else:
        raise argparse.ArgumentError(None, f"unsupported command: {command}")


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in values
    ground_truth = "--ground-truth" in values
    # Global switches work before or after a subcommand.
    values = [value for value in values if value not in {"--json", "--ground-truth"}]
    if json_mode:
        values.insert(0, "--json")
    if ground_truth:
        values.insert(0, "--ground-truth")
    output = Output(json_mode=json_mode)
    parser = build_parser()
    try:
        args = parser.parse_args(values)
        dispatch(args, parser, output)
        return int(ExitCode.OK)
    except argparse.ArgumentError as exc:
        output.error("parse", str(exc), int(ExitCode.USAGE))
        return int(ExitCode.USAGE)
    except KeyboardInterrupt:
        output.error(
            "interrupted",
            "operation interrupted; bounded cleanup was attempted",
            int(ExitCode.CANCELLED),
        )
        return int(ExitCode.CANCELLED)
    except VulnDockyardError as exc:
        command = next((value for value in values if not value.startswith("-")), "unknown")
        output.error(command, str(exc), int(exc.exit_code))
        return int(exc.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
