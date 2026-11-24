@echo off
if not exist out mkdir out
javac -cp "lib/*" -d out src\Server.java && java -cp "out;lib/*" Server
pause
