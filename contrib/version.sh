#!/bin/sh
# Prints the Netlens version: <major.minor from the VERSION file>.<commits since VERSION last changed>.
# The commit that changes VERSION is therefore <major.minor>.0 and every later commit raises the last number by one.
# Usage: contrib/version.sh [repository folder]
cd "${1:-.}" || exit 1
base=$(git log -1 --format=%H -- VERSION)
echo "$(tr -d '[:space:]' < VERSION).$(git rev-list --count "${base}..HEAD")"
