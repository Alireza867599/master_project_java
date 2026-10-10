#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p classes
javac -encoding UTF-8 -d classes src/*.java
javac -encoding UTF-8 -cp classes -d classes tests/*.java
jar --create --file sfdac-java.jar -C classes .
echo 'Compiled all Java source files and created sfdac-java.jar'
