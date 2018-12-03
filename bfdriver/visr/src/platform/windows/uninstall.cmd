@ECHO OFF
SETLOCAL

:: WARNING! The following variable will be different on every system! You need
:: to look up the "Published Name" field reported from pnputil during
:: installation, or find it using 'pnputil /enum-drivers'
SET published_name="oem8.inf"

pnputil /delete-driver %published_name%

ENDLOCAL
@ECHO ON
