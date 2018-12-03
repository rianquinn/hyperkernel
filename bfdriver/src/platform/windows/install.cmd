@ECHO OFF
SETLOCAL

SET driver_path="x64\Release\visr\visr.inf"

pnputil /add-driver %driver_path%

ENDLOCAL
@ECHO ON
