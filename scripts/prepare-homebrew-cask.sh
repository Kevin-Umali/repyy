#!/bin/sh
set -eu

cask=${1:-dist/homebrew/Casks/repyy.rb}
marker='  # No zap stanza required'

if [ ! -f "$cask" ]; then
  echo "cask not found: $cask" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]*(postflight|postflight_steps)[[:space:]]+do' "$cask"; then
  echo "cask already contains a postflight stanza: $cask" >&2
  exit 1
fi

marker_count=$(grep -Fxc "$marker" "$cask" || true)
if [ "$marker_count" -ne 1 ]; then
  echo "expected exactly one GoReleaser zap marker in $cask, found $marker_count" >&2
  exit 1
fi

temporary="${cask}.tmp"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

awk '
  $0 == "  # No zap stanza required" {
    print "  postflight_steps do"
    print "    on_macos do"
    print "      run \"/usr/bin/xattr\", args: [\"-dr\", \"com.apple.quarantine\", \"{{staged_path}}/repyy\"]"
    print "    end"
    print "  end"
    print ""
  }
  { print }
' "$cask" > "$temporary"

mv "$temporary" "$cask"
trap - EXIT HUP INT TERM

grep -Fq 'postflight_steps do' "$cask"
if grep -Eq '^[[:space:]]*postflight[[:space:]]+do' "$cask"; then
  echo "deprecated postflight stanza remains in $cask" >&2
  exit 1
fi
