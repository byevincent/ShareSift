@echo off
set PASSWORD=FAKE-Sup3rS3cret2024!
set DB_HOST=dbprod.corp.local
mysql -uroot -p%PASSWORD% -h %DB_HOST% -e "SELECT NOW()"
