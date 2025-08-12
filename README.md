## Bst Single Updater

A wrapper for [auto_updater](https://gitlab.com/BuildStream/infrastructure/gitlab-merge-request-generator)
to create a single MR with all updates instead of one MR per update.

### Install

```sh
pip install --user git+https://github.com/bbhtt/bst-single-updater.git@v0.0.0#egg=bst_single_updater
```

### Usage

Note, that it is best to run it inside a docker image coming with `bst,
auto_updater` and all other dependencies, such as
`ghcr.io/bbhtt/fdsdk-build-env:latest`.

```sh
bst-single-updater --base-branch master --element foobar.bst --extra-auto_updater-opts="--nodeps"
```

```
Bst single updater

A wrapper for auto_updater to create a single MR with all
updates instead of one MR per update.

options:
  -h, --help            Show this help message and exit
  --version             Show the version and exit
  --no-cleanup          Do not delete auto_updater local branches
  --base-branch         Specify the base branch
  --element             Specify the element auto_updater will track
  --extra-auto_updater-opts
                        Extra options to pass to auto_updater
  --push                Push the branch to the remote repository
  --create-mr           Create a Gitlab merge request (implies --push)
```

### Development

```sh
uv run ruff format
uv run ruff check --fix --exit-non-zero-on-fix
uv run mypy .
```
