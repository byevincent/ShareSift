@echo off
set "PGPASSWORD=FAKE-W3lc0m3-2024!"
set "PGUSER=postgres"
pg_dump -h db.corp.local -U postgres mydb > backup.sql
