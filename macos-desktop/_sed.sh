#!/usr/bin/env bash
# Portable in-place sed (GNU vs BSD).
sed_inplace() {
	if sed --version >/dev/null 2>&1; then
		sed -i "$@"
	else
		local expr="${1:?}"
		shift
		sed -i '' "$expr" "$@"
	fi
}
