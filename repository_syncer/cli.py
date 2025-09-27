import base64
import dataclasses
import getpass
import logging
import os
import subprocess
import tempfile
from pathlib import PosixPath
from typing import Optional, Dict

import click
import requests
import yaml

logger = logging.getLogger(__name__)
manage_environment = os.environ.get("NO_HOME") is not None
ssh_auth_socket = PosixPath("/tmp/ssh-auth.sock")
home_dir = (
    PosixPath("/workspace")
    if manage_environment
    else PosixPath(os.path.expanduser("~"))
)


@dataclasses.dataclass
class RepoConfig:
    source: str
    target: str


def _calculate_process_env() -> Dict[str, str]:
    # Copy from system
    proc_env = {k: v for k, v in os.environ.items()}

    # Override key values
    proc_env |= {
        "SSH_AUTH_SOCK": ssh_auth_socket.as_posix(),
        "HOME": home_dir.as_posix(),
    }

    # NSS wrapper
    try:
        getpass.getuser()
    except OSError:
        # No passwd entry for current uid... fake one
        uid = os.getuid()
        with (home_dir / "passwd").open("w") as fh:
            fh.write(f"runner:x:{uid}:{uid}:runner gecos:/workspace:/bin/false\n")

        with (home_dir / "group").open("w") as fh:
            fh.write(f"runner:x:{uid}:\n")

        proc_env |= {
            "LD_PRELOAD": "/layers/heroku_deb-packages/packages/usr/lib/x86_64-linux-gnu/libnss_wrapper.so",
            "NSS_WRAPPER_PASSWD": (home_dir / "passwd").as_posix(),
            "NSS_WRAPPER_GROUP": (home_dir / "group").as_posix(),
        }

    return proc_env


def _setup_environment():
    # SSH
    ssh_dir = home_dir / ".ssh"
    if not ssh_dir.is_dir():
        logger.info(f"Creating {ssh_dir.as_posix()}")
        ssh_dir.parent.mkdir(exist_ok=True, parents=True)
        ssh_dir.mkdir(mode=0o700)

    # SSH known hosts
    if not manage_environment:
        logger.info(f"Skipping ssh known_hosts file due to manage_environment")
    else:
        logger.info("Downloading production known_hosts file")
        r = requests.get(
            "https://config-master.wikimedia.org/known_hosts",
            headers={"User-Agent": "ClueBot Repository Syncer"},
        )
        r.raise_for_status()
        with (ssh_dir / "known_hosts").open("w") as fh:
            fh.write(r.text)

    # SSH config
    if not manage_environment:
        logger.info(f"Skipping ssh config entry due to manage_environment")
    else:
        logger.info("Creating config entry for gitlab")
        with (ssh_dir / "config").open("w") as fh:
            fh.write("Host gitlab.wikimedia.org\n")
            fh.write("\tStrictHostKeyChecking Yes\n")
            fh.write("\tUser git\n")

    # SSH key
    encoded_ssh_key = os.environ.get("GITLAB_SSH_KEY")
    if not encoded_ssh_key:
        raise RuntimeError(f"Missing ssh-key, ensure GITLAB_SSH_KEY is set")

    if not ssh_auth_socket.is_socket():
        logger.info(f"Starting ssh-agent on {ssh_auth_socket.as_posix()}")
        subprocess.check_call(["ssh-agent", "-a", ssh_auth_socket.as_posix()])

    logger.info(f"Adding ssh-key to ssh-agent running on {ssh_auth_socket.as_posix()}")
    ssh_key = base64.b64decode(encoded_ssh_key.encode("utf-8"))
    p = subprocess.Popen(
        ["ssh-add", "-"],
        stdin=subprocess.PIPE,
        env={"SSH_AUTH_SOCK": ssh_auth_socket.as_posix()},
    )
    p.communicate(ssh_key)


def _load_config(config_path: PosixPath) -> Dict[str, RepoConfig]:
    if not config_path.is_file():
        raise RuntimeError(f"Specified config is not a file: {config_path.as_posix()}")

    with config_path.open("r") as fh:
        return {
            name: RepoConfig(source=config["source"], target=config["target"])
            for name, config in yaml.load(fh.read(), Loader=yaml.SafeLoader).items()
        }


def _mirror(source: str, target: str) -> None:
    with tempfile.TemporaryDirectory() as path:
        tmp_path = PosixPath(path)

        git_cmd = ["git"]
        git_env = _calculate_process_env()

        # Pack puts things in a very specific place (.deb extract)
        pack_git_path = PosixPath("/layers/heroku_deb-packages/packages/usr/bin/git")
        if pack_git_path.is_file():
            git_cmd = ["/cnb/lifecycle/launcher", pack_git_path.as_posix()]
            git_env |= {
                "GIT_TEMPLATE_DIR": "/layers/heroku_deb-packages/packages/usr/share/git-core/templates",
                "PATH": f'{git_env["PATH"]}:/layers/heroku_deb-packages/packages/usr/lib/git-core/',
            }

        logger.info(f"Mirroring {source} -> {target}")
        p = subprocess.Popen(
            git_cmd + ["clone", "--mirror", source, tmp_path.as_posix()],
            env=git_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            logger.error(f"Failed to clone repo [{p.returncode}] {stdout} / {stderr}")
            return

        # Git checks the home dir ownership, explicitly mark it as safe
        if manage_environment:
            p = subprocess.Popen(
                git_cmd
                + [
                    "config",
                    "--global",
                    "--add",
                    "safe.directory",
                    home_dir.as_posix(),
                ],
                env=git_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                logger.error(
                    f"Failed to mark {home_dir.as_posix()} as safe [{p.returncode}] {stdout} / {stderr}"
                )
                return

        p = subprocess.Popen(
            git_cmd + ["-C", tmp_path.as_posix(), "push", "--mirror", target],
            env=git_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            logger.error(f"Failed to push repo [{p.returncode}] {stdout} / {stderr}")
            return


@click.group()
def cli():
    logging.basicConfig(level=logging.DEBUG)


@click.option("--target-repo", default=None)
@click.option(
    "--config-path",
    default=(PosixPath(__file__).parent.parent / "mirror.yaml").as_posix(),
)
@cli.command()
def sync(config_path: str, target_repo: Optional[str] = None):
    _setup_environment()

    config = _load_config(PosixPath(config_path))

    for name, repo_config in config.items():
        if target_repo and name != target_repo:
            logger.debug(f"Skipping {name} due to target-repo ({target_repo})")
            continue

        _mirror(repo_config.source, repo_config.target)


if __name__ == "__main__":
    cli()
