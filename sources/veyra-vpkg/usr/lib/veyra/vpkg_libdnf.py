"""Small, policy-focused libdnf5 API adapter used by vpkg.

This module intentionally does not expose a shell command surface. Every
transaction is resolved and executed through libdnf5's Python bindings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class LibdnfError(RuntimeError):
    pass


@dataclass(frozen=True)
class PackageChange:
    action: int
    name: str
    nevra: str
    repo_id: str
    path: str


@dataclass(frozen=True)
class TransactionResult:
    changes: tuple[PackageChange, ...]
    transaction: object


def _bindings():
    try:
        import libdnf5
    except ImportError as error:
        raise LibdnfError("The python3-libdnf5 bindings are required by vpkg.") from error
    return libdnf5


def _set_option(config, name: str, value) -> None:
    getter = getattr(config, f"get_{name}_option", None)
    if getter is None:
        raise LibdnfError(f"libdnf5 does not expose the required {name} configuration option.")
    option = getter()
    try:
        option.set(value)
    except TypeError:
        # libdnf5's SWIG bindings use both Option::set(value) and
        # Option::set(priority, value), depending on option type.
        option.set(option.Priority_RUNTIME, value)


class Session:
    """One immutable libdnf5 configuration/repository/solver session."""

    def __init__(
        self,
        *,
        installroot: Path,
        releasever: str,
        repo_ids: Iterable[str],
        cache_dir: Path,
        history_dir: Path,
        persist_dir: Path,
        state_dir: Path,
        no_scripts: bool = True,
        refresh: bool = False,
    ) -> None:
        self.libdnf5 = _bindings()
        self.repo_ids = tuple(dict.fromkeys(repo_ids))
        if not releasever.isdecimal():
            raise LibdnfError("The base releasever must be a decimal Fedora version.")

        self.base = self.libdnf5.base.Base()
        config = self.base.get_config()
        _set_option(config, "config_file_path", "/etc/dnf/dnf.conf")
        _set_option(config, "installroot", str(installroot))
        self.base.load_config()

        # Explicitly use host repository definitions while directing all
        # package database and cache writes into vpkg-owned locations.
        config = self.base.get_config()
        settings = {
            "config_file_path": "/etc/dnf/dnf.conf",
            "installroot": str(installroot),
            "reposdir": ["/etc/yum.repos.d", "/etc/distro.repos.d", "/usr/share/dnf5/repos.d"],
            "plugins": False,
            "system_cachedir": str(cache_dir),
            "cachedir": str(cache_dir),
            "transaction_history_dir": str(history_dir),
            "persistdir": str(persist_dir),
            "system_state_dir": str(state_dir),
            "install_weak_deps": False,
            "keepcache": True,
            "pkg_gpgcheck": True,
            "localpkg_gpgcheck": True,
            "assumeyes": True,
            "skip_broken": False,
            "skip_unavailable": False,
            "best": True,
        }
        for name, value in settings.items():
            _set_option(config, name, value)
        if no_scripts:
            _set_option(config, "tsflags", ["noscripts", "notriggers"])

        self.base.get_vars().get().set(
            "releasever", releasever, self.base.get_vars().get().Priority_RUNTIME
        )
        self.base.setup()
        self.base.get_repo_sack().create_repos_from_system_configuration()
        query = self.libdnf5.repo.RepoQuery(self.base)
        self._repo_callbacks = []
        for repo in query.list():
            repo_config = repo.get_config()
            _set_option(repo_config, "enabled", repo.get_id() in self.repo_ids)
            _set_option(repo_config, "pkg_gpgcheck", True)
            if repo.get_id() in {"veyra-main", "veyra-testing"}:
                trusted_key = "file:///usr/share/veyra/RPM-GPG-KEY-VEYRA"
                class PinnedRepoKeyCallbacks(self.libdnf5.repo.RepoCallbacks):
                    def repokey_import(self, key_info) -> bool:
                        return key_info.get_url() == trusted_key

                    def repokey_imported(self, key_info) -> None:
                        del key_info

                callbacks = PinnedRepoKeyCallbacks()
                repo.set_callbacks(callbacks)
                self._repo_callbacks.append(callbacks)
            if refresh and repo.get_id() in self.repo_ids:
                _set_option(repo_config, "metadata_expire", 0)
        sack = self.base.get_repo_sack()
        sack.load_repos()
        self.refresh = refresh

    def resolve(
        self,
        action: str,
        specifications: Iterable[str] = (),
        *,
        installed_from: Iterable[str] = (),
        local_rpms: Iterable[Path] = (),
    ) -> TransactionResult:
        try:
            return self._resolve(action, specifications, installed_from=installed_from, local_rpms=local_rpms)
        except LibdnfError:
            raise
        except Exception as error:
            raise LibdnfError(f"libdnf5 transaction failed: {error}") from error

    def _resolve(
        self,
        action: str,
        specifications: Iterable[str],
        *,
        installed_from: Iterable[str],
        local_rpms: Iterable[Path],
    ) -> TransactionResult:
        libdnf5 = self.libdnf5
        goal = libdnf5.base.Goal(self.base)
        settings = libdnf5.base.GoalJobSettings()
        settings.set_skip_broken(False)
        settings.set_skip_unavailable(False)
        if self.repo_ids:
            settings.set_to_repo_ids(list(self.repo_ids))
        if installed_from:
            settings.set_from_repo_ids(list(installed_from))

        paths = [str(path) for path in local_rpms]
        local_packages = {}
        if paths:
            local_packages = self.base.get_repo_sack().add_cmdline_packages(paths, True)
        specs = list(specifications)
        if action != "remove" and not self.repo_ids:
            raise LibdnfError("No trusted package repositories are enabled for this transaction.")
        if action == "install":
            for spec in specs:
                goal.add_install(spec, settings)
            for path in paths:
                goal.add_install(local_packages[path], settings)
        elif action == "remove":
            for spec in specs:
                goal.add_remove(spec, settings)
        elif action == "upgrade":
            goal.add_upgrade(settings, False)
        elif action == "repo-sync":
            goal.add_rpm_distro_sync(settings)
        else:
            raise LibdnfError(f"Unsupported libdnf5 transaction action: {action}")

        transaction = goal.resolve()
        if transaction.get_problems() != libdnf5.base.GoalProblem_NO_PROBLEM:
            details = "\n".join(transaction.get_resolve_logs_as_strings())
            raise LibdnfError(f"Could not resolve the RPM transaction:\n{details}")
        if transaction.empty():
            return TransactionResult((), transaction)
        transaction.download()
        if not transaction.check_gpg_signatures():
            raise LibdnfError("libdnf5 rejected one or more RPM package signatures.")

        changes = []
        for item in transaction.get_transaction_packages():
            package = item.get_package()
            changes.append(
                PackageChange(
                    action=item.get_action(),
                    name=package.get_name(),
                    nevra=package.get_full_nevra(),
                    repo_id=package.get_repo_id(),
                    path=package.get_package_path(),
                )
            )
        run_result = transaction.run()
        if run_result != transaction.TransactionRunResult_SUCCESS:
            raise LibdnfError(
                "libdnf5 transaction failed: "
                + transaction.transaction_result_to_string(run_result)
            )
        return TransactionResult(tuple(changes), transaction)


def package_query(installroot: Path, releasever: str, repo_ids: Iterable[str], cache_dir: Path):
    """Load selected repos and return query-ready Base and PackageQuery."""
    session = Session(
        installroot=installroot,
        releasever=releasever,
        repo_ids=repo_ids,
        cache_dir=cache_dir,
        history_dir=cache_dir / "history",
        persist_dir=cache_dir / "persist",
        state_dir=cache_dir / "state",
    )
    return session.base, session.libdnf5.rpm.PackageQuery(session.base)
