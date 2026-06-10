@echo off
set SVCPASS=FAKE-SvcRestart-2024!
sc.exe \\srv01 stop CorpService
sc.exe \\srv01 start CorpService obj= corp\svc_runner password= %SVCPASS%
