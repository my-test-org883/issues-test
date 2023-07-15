#!/usr/bin/env bash

docker run --rm -v "$(pwd)/code/rails2:/code" presidentbeef/brakeman --color -f sarif
