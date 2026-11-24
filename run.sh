#!/bin/sh
# Needs Java 17+ and lib/h2-2.2.224.jar (see README)
mkdir -p out && javac -cp "lib/*" -d out src/Server.java && java -cp "out:lib/*" Server
