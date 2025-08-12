import argparse
import datetime
import logging
import os
import re
import shlex
import shutil
import subprocess
import textwrap
from subprocess import CompletedProcess
from typing import TYPE_CHECKING

try:
    import gitlab

    GITLAB_IMPORTED = True
except ImportError:
    GITLAB_IMPORTED = False

if TYPE_CHECKING and not GITLAB_IMPORTED:
    import gitlab

from . import __version__

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def run_command(
    command: list[str],
    check: bool = True,
    capture_output: bool = False,
    cwd: str | None = None,
    message: str | None = None,
    warn: bool = False,
) -> CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=check,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            text=True,
            cwd=cwd,
        )
    except subprocess.CalledProcessError as e:
        if message:
            if warn:
                logging.warning("%s: %s", message, e.stderr.strip() if e.stderr else "")
            else:
                logging.error("%s: %s", message, e.stderr.strip() if e.stderr else "")
        else:
            logging.error(
                "Command failed: %s\nError: %s",
                " ".join(command),
                e.stderr.strip() if e.stderr else "",
            )
        raise


def run_git(
    args: list[str],
    repo_path: str | None = None,
    capture_output: bool = False,
    message: str | None = None,
    warn: bool = False,
) -> CompletedProcess[str]:
    if repo_path is None:
        repo_path = str(os.getcwd())
    command = ["git", "-c", "credential.interactive=false", "-C", repo_path, *args]
    logging.info("Running command: %s", " ".join(command))
    return run_command(
        command, capture_output=capture_output, message=message, warn=warn
    )


def is_cmd_present(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def is_git_dir() -> bool:
    try:
        return run_git(["rev-parse"]).returncode == 0
    except subprocess.CalledProcessError:
        return False


def is_dirty() -> bool:
    try:
        result = run_git(["status", "--porcelain"], capture_output=True)
        return bool(result.stdout.strip())
    except subprocess.CalledProcessError:
        return True


def get_local_branches() -> list[str]:
    try:
        result = run_git(["branch"], capture_output=True)
        return [
            line.strip().lstrip("* ").strip() for line in result.stdout.splitlines()
        ]
    except subprocess.CalledProcessError as e:
        logging.error("Failed to get local branches: %s", e.stderr or e)
        return []


def delete_branch(branch: str) -> bool:
    try:
        return run_git(["branch", "-D", branch]).returncode == 0
    except subprocess.CalledProcessError as e:
        logging.error("Failed to delete branch '%s': %s", branch, e.stderr or e)
        return False


def element_exists(element: str) -> bool:
    command = [
        "bst",
        "--no-interactive",
        "show",
        "--deps",
        "none",
        "-f",
        "%{name}",
        element,
    ]
    try:
        run_command(
            command,
            message=f"Did not find element: {element}",
        )
        return True
    except subprocess.CalledProcessError:
        return False


def run_updater(branch: str, element: str, extra_opts: str = "") -> bool:
    if not element_exists(element):
        return False

    command = [
        "auto_updater",
        f"--base_branch={branch}",
        "--nobuild",
        "--overwrite",
        "--shuffle-branches",
        "--on_track_error=continue",
    ]
    if extra_opts:
        command.extend(shlex.split(extra_opts))
    command.append(element)

    logging.info("Running command: %s", " ".join(command))
    try:
        run_command(command)
        return True
    except subprocess.CalledProcessError as err:
        logging.error(
            "Failed to run auto_updater: %s",
            err.stderr.strip() if err.stderr else str(err),
        )
        return False


def create_branch(base_branch: str) -> str | None:
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    branch_name = f"update-singlemr/{base_branch}/{timestamp}"
    try:
        success = run_git(["checkout", "-b", branch_name, base_branch]).returncode == 0
        return branch_name if success else None
    except subprocess.CalledProcessError as e:
        logging.error("Failed to create branch '%s': %s", branch_name, e.stderr or e)
        return None


def reformat_commit_message(commit_message: str) -> str:
    pattern = r"elements/(?:.*/)?(.+?)\.(?:bst|yml)\s+to\s+(.+)"
    matched = re.search(pattern, commit_message)
    if matched:
        element_name = matched.group(1).split("/")[-1]
        updated_version = matched.group(2)
        return f"{element_name}: Update to {updated_version}"
    return commit_message


def checkout_branch(branch: str) -> bool:
    try:
        return run_git(["checkout", branch]).returncode == 0
    except subprocess.CalledProcessError as e:
        logging.error("Failed to checkout branch '%s': %s", branch, e.stderr or e)
        return False


def cleanup_branches(branches: list[str], base_branch: str, branch_regex: str) -> bool:
    if not checkout_branch(base_branch):
        return False
    clean_branches = [branch for branch in branches if re.match(branch_regex, branch)]
    return all(delete_branch(branch) for branch in clean_branches)


def get_top_commit() -> str | None:
    try:
        result = run_git(["rev-parse", "HEAD"], capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error("Failed to get HEAD commit: %s", e.stderr or e)
        return None


def cherry_pick_commit(commit_hash: str) -> bool:
    try:
        run_git(["cherry-pick", commit_hash])
        return True
    except subprocess.CalledProcessError as e:
        logging.error(
            "Failed to cherry-pick commit '%s': %s", commit_hash, e.stderr or e
        )
        return False


def get_commit_message() -> str | None:
    try:
        result = run_git(["log", "-1", "--pretty=%B"], capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error("Failed to get commit message: %s", e.stderr or e)
        return None


def amend_commit_message(new_message: str) -> bool:
    try:
        run_git(["commit", "--amend", "-m", new_message])
        return True
    except subprocess.CalledProcessError as e:
        logging.error("Failed to amend commit message: %s", e.stderr or e)
        return False


def cherry_pick_top_commit(branch_list: list[str], single_branch: str) -> bool:
    for branch in branch_list:
        if not checkout_branch(branch):
            continue

        top_commit = get_top_commit()
        if not top_commit:
            continue

        if not checkout_branch(single_branch):
            return False

        if not cherry_pick_commit(top_commit):
            continue

        commit_message = get_commit_message()
        if commit_message:
            new_message = reformat_commit_message(commit_message)
            amend_commit_message(new_message)

    return True


def push_branch_to_remote(branch: str, remote: str = "origin") -> bool:
    if not checkout_branch(branch):
        return False
    try:
        run_git(
            ["push", "--set-upstream", "-f", remote, branch],
            message=f"Failed to push branch {branch} to {remote}",
        )
        logging.info("Pushed %s to %s", branch, remote)
        return True
    except subprocess.CalledProcessError as e:
        logging.error("Failed to push branch '%s': %s", branch, e.stderr or e)
        return False


def remove_remote_branch(project: "gitlab.v4.objects.Project") -> None:
    branch_regex = r"^update-singlemr/[^/]+/\d{14}$"
    branches = project.branches.list(iterator=True, regex=branch_regex)
    open_mrs = project.mergerequests.list(state="opened", iterator=True)
    branch_names = {branch.name for branch in branches}
    open_mr_branches = {
        mr.source_branch for mr in open_mrs if re.match(branch_regex, mr.source_branch)
    }
    branches_without_open_mrs = branch_names - open_mr_branches
    project.delete_merged_branches()
    for branch in branches_without_open_mrs:
        logging.info("Deleting branch: %s", branch)
        project.branches.delete(branch)


def create_merge_request(
    source_branch: str,
    base_branch: str,
    mr_title: str = "(Automated) Update elements",
    clear_br: bool = True,
) -> bool:
    token = os.environ.get("GITLAB_API_KEY") or os.environ.get("FREEDESKTOP_API_TOKEN")
    if not token:
        logging.error("GITLAB_API_KEY is not defined")
        return False

    if not (
        (project_id := os.environ.get("CI_PROJECT_ID"))
        and (gitlab_url := os.environ.get("CI_SERVER_URL"))
    ):
        logging.error(
            "CI_PROJECT_ID or CI_SERVER_URL is not defined. "
            "Likely running outside of GitLab pipeline"
        )
        return False

    try:
        gl = gitlab.Gitlab(gitlab_url, private_token=token)
        project = gl.projects.get(project_id, lazy=True)
        mr = project.mergerequests.create(
            {
                "source_branch": source_branch,
                "target_branch": base_branch,
                "title": mr_title,
            }
        )
        logging.info("Merge request created: %s", mr.web_url)
        if clear_br:
            remove_remote_branch(project)
        return True
    except gitlab.exceptions.GitlabError as e:
        logging.error("Failed to create merge request: %s", e)
        return False


def validate_environment() -> bool:
    validations = [
        (is_cmd_present("git"), "Unable to find git in PATH"),
        (is_cmd_present("bst"), "Unable to find bst in PATH"),
        (is_cmd_present("auto_updater"), "Unable to find auto_updater in PATH"),
        (is_git_dir(), "Current directory is not a git repository"),
        (not is_dirty(), "The repository is dirty"),
    ]
    for valid, msg in validations:
        if not valid:
            logging.error(msg)
            return False
    return True


def main() -> int:
    description = textwrap.dedent("""\
        Bst single updater

        A wrapper for auto_updater to create a single MR with all
        updates instead of one MR per update.
    """)
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the version and exit",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Do not delete auto_updater local branches",
    )
    parser.add_argument(
        "--base-branch",
        type=str,
        required=True,
        metavar="",
        help="Specify the base branch",
    )
    parser.add_argument(
        "--element",
        type=str,
        required=True,
        metavar="",
        help="Specify the element auto_updater will track",
    )
    parser.add_argument(
        "--extra-auto_updater-opts",
        type=str,
        default="",
        metavar="",
        help="Extra options to pass to auto_updater",
    )
    parser.add_argument(
        "--push",
        default=False,
        action="store_true",
        help="Push the branch to the remote repository",
    )
    parser.add_argument(
        "--create-mr",
        default=False,
        action="store_true",
        help="Create a Gitlab merge request (implies --push)",
    )
    args = parser.parse_args()

    branch_regex = (
        rf"^update/"
        r".+[.](bst|yml)"
        rf"-diff_md5-.*-for-{args.base_branch}$"
    )

    if not validate_environment():
        return 1

    if args.create_mr:
        args.push = True
        if not GITLAB_IMPORTED:
            logging.error("--create-mr is used but python-gitlab was not imported")
            return 1

    branches = get_local_branches()
    if not branches:
        logging.error("No local git branches found")
        return 1

    if not (
        args.no_cleanup or cleanup_branches(branches, args.base_branch, branch_regex)
    ):
        return 1

    if not run_updater(args.base_branch, args.element, args.extra_auto_updater_opts):
        return 1

    if not is_dirty():
        single_branch = create_branch(args.base_branch)

        if not single_branch:
            logging.error("Failed to create new branch")
            return 1

        updater_branches = [
            branch for branch in get_local_branches() if re.match(branch_regex, branch)
        ]
        if not cherry_pick_top_commit(updater_branches, single_branch):
            return 1
        if not (
            args.no_cleanup
            or cleanup_branches(branches, args.base_branch, branch_regex)
        ):
            return 1
        if not checkout_branch(single_branch):
            logging.error("Failed to checkout unified branch")
            return 1
        if args.push:
            push_ret = push_branch_to_remote(single_branch)
            if not push_ret:
                return 1
            if (
                GITLAB_IMPORTED
                and args.create_mr
                and push_ret
                and not create_merge_request(single_branch, args.base_branch)
            ):
                return 1

    else:
        logging.error("The repository is dirty after running auto_updater")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
