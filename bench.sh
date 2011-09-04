#!/bin/sh
MAVEN=mvn
${MAVEN} compile
command -v ${MAVEN} >/dev/null || { echo "Error: mvn not found or Maven not installed." >&2; exit 1; }
${MAVEN} exec:java -Dexec.mainClass="net.sf.ntru.demo.Benchmark" -Dexec.args="$@"
