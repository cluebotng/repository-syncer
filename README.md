# ClueBot Repository Syncer

`git` mirror that performs a one way sync from GitHub (authoritative) to GitLab.

## Testing locally

```
$ export GITLAB_SSH_KEY=$(base64 < /Users/damian/.ssh/cluebot-repository-syncer)
$ python repository_syncer/cli.py 
```

## Build locally

```
$ pack build --builder heroku/builder:24 repository-syncer
```

## Production configuration

Expected secrets:

* `GITLAB_SSH_KEY` - private ssh key to access GitLab
