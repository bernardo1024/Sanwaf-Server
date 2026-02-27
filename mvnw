#!/bin/bash
source "$(dirname "$0")/.mvn/jdk.env"
exec mvn "$@"
