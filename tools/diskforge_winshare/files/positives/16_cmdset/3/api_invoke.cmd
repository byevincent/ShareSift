@echo off
rem corp API daily pull
set "API_KEY=FAKE-ApiKey-2024-aBcDeF123456"
curl -H "Authorization: Bearer %API_KEY%" https://api.corp.local/v1/data
