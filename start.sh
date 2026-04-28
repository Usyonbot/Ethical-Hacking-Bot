#!/bin/bash
BASE="$(cd "$(dirname "$0")" && pwd)"
export GOPATH="$BASE/go"
export GEM_HOME="$BASE/gems"
export GEM_PATH="$BASE/gems"
export PATH="$BASE/ehb-env/bin:$BASE/go/bin:$BASE/gems/bin:$BASE/tools/exploitdb:/opt/homebrew/bin:$PATH"

source "$BASE/ehb-env/bin/activate"
python3 "$BASE/ehb_server.py"
