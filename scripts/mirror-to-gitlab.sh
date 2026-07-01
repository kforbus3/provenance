#!/usr/bin/env bash
# Mirror new commits from the current branch onto a second remote, re-authored
# with a different identity.
#
# Fleet Terminal is kept on two remotes with equivalent content but different
# commit identities: the public `github` remote (a scrubbed history with a
# GitHub no-reply author) and a private GitLab remote (your real identity). Those
# two histories are DISJOINT — the public side was rewritten to remove personal
# emails — so a normal `git push` to GitLab won't fast-forward.
#
# This script finds the last commit already on GitLab by matching tree hashes,
# replays everything after it onto the GitLab tip re-authored with your GitLab
# identity, then does a normal fast-forward push. No force-push; GitLab's history
# and identity are preserved. It is idempotent: with nothing new, it does nothing.
#
# Configure once (values live in .git/config and are never committed):
#   git config fleet.gitlabRemote origin
#   git config fleet.gitlabBranch main
#   git config fleet.gitlabName   "Your Name"
#   git config fleet.gitlabEmail  "you@example.com"
# Any of these can be overridden per-run via the environment variables
# GITLAB_REMOTE / GITLAB_BRANCH / GITLAB_NAME / GITLAB_EMAIL.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
cfg() { git config --get "$1" 2>/dev/null || true; }

REMOTE="${GITLAB_REMOTE:-$(cfg fleet.gitlabRemote)}"; REMOTE="${REMOTE:-origin}"
BRANCH="${GITLAB_BRANCH:-$(cfg fleet.gitlabBranch)}"; BRANCH="${BRANCH:-main}"
NAME="${GITLAB_NAME:-$(cfg fleet.gitlabName)}"
EMAIL="${GITLAB_EMAIL:-$(cfg fleet.gitlabEmail)}"

[ -n "$NAME" ]  || die "GitLab author name not set  (git config fleet.gitlabName \"...\"  or GITLAB_NAME=...)"
[ -n "$EMAIL" ] || die "GitLab author email not set (git config fleet.gitlabEmail \"...\" or GITLAB_EMAIL=...)"
git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
git diff --quiet && git diff --cached --quiet || die "working tree not clean — commit or stash first"

SRC="$(git symbolic-ref --short HEAD)" || die "detached HEAD — check out the branch to mirror"

echo "Fetching $REMOTE/$BRANCH ..."
git fetch --quiet "$REMOTE" "$BRANCH" || die "could not fetch $REMOTE/$BRANCH"
REMOTE_REF="$REMOTE/$BRANCH"
REMOTE_TREE="$(git rev-parse "$REMOTE_REF^{tree}")"

# The last local commit whose tree already matches the GitLab tip is the last
# point that was synced; everything after it is what GitLab is missing.
BASE=""
for c in $(git rev-list "$SRC"); do
  if [ "$(git rev-parse "$c^{tree}")" = "$REMOTE_TREE" ]; then BASE="$c"; break; fi
done
[ -n "$BASE" ] || die "no commit on '$SRC' has the same tree as $REMOTE_REF — the two histories have diverged in content (someone committed to GitLab directly?); reconcile manually"

if [ "$BASE" = "$(git rev-parse "$SRC")" ]; then
  echo "Nothing to mirror — $REMOTE_REF already matches '$SRC'."
  exit 0
fi

COUNT="$(git rev-list --count "$BASE..$SRC")"
echo "Replaying $COUNT commit(s) onto $REMOTE_REF as $NAME <$EMAIL> ..."

TMP="mirror-gitlab-$$"
cleanup() {
  git cherry-pick --abort >/dev/null 2>&1 || true
  git checkout --quiet "$SRC" >/dev/null 2>&1 || true
  git branch -D "$TMP" >/dev/null 2>&1 || true
  git for-each-ref --format='%(refname)' refs/original/ 2>/dev/null | xargs -r -n1 git update-ref -d 2>/dev/null || true
}
trap cleanup EXIT

git checkout --quiet -b "$TMP" "$REMOTE_REF"
git cherry-pick "$BASE..$SRC" >/dev/null

# Re-author the replayed commits with the GitLab identity (author + committer).
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --env-filter "
export GIT_AUTHOR_NAME='$NAME'
export GIT_AUTHOR_EMAIL='$EMAIL'
export GIT_COMMITTER_NAME='$NAME'
export GIT_COMMITTER_EMAIL='$EMAIL'
" -- "$REMOTE_REF..HEAD" >/dev/null 2>&1

# Safety net: it must be a fast-forward and content-identical to the source.
git merge-base --is-ancestor "$REMOTE_REF" HEAD || die "internal: replay is not a fast-forward of $REMOTE_REF"
git diff --quiet HEAD "$SRC" || die "internal: replayed tree differs from '$SRC'"

echo "Pushing to $REMOTE $BRANCH (fast-forward) ..."
git push "$REMOTE" "HEAD:$BRANCH"

echo "Done — $REMOTE/$BRANCH now matches '$SRC' with your GitLab identity."
