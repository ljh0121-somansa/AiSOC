#!/bin/bash

if [[ ! -e .git ]]
then
    echo "initialize git first"
    exit -1
fi

git submodule add https://gitlab.somansa.com/crowmania/harness-dev.git .harness

mkdir -p hypercortex workspace .pi

cat > .pi/settings.json << EOF
{
  "extensions": [
    "../.harness/harness/extensions/harness-prompts.ts"
  ]
}
EOF

echo "initialized!"

