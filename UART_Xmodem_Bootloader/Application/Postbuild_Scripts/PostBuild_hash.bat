@ECHO off

REM Note on input parameters
REM Param1: Binary file (with path)

SET "binname=%~n1"
SET "outputname=SIGMA_Embedded_APP_UART"
SET "inpath=..\Debug"
SET "temppath=.\"
SET "outpath=..\Out"
SET "utilpath=%~d0%~p0"
SET "input_bin="%inpath%\%binname%.bin""

SET "out_padbin="%temppath%\%outputname%_with_pad.bin""
SET "out_bin_without_header="%temppath%\%outputname%_bin_without_header.bin""
SET "out_hashbin="%temppath%\%outputname%_with_hash.bin""
SET "out_toFlash="%outpath%\%outputname%_toFlash.bin""

SET TMP_DIR=.\tmp
SET "hashvalue=%TMP_DIR%\Hash.sha"

SET DIR_OPENSSL=%utilpath%\ExtTools
SET DIR_TOOLS=%utilpath%\ExtTools
SET OPENSSL=%DIR_OPENSSL%\openssl.exe 
SET SREC=%DIR_TOOLS%\srec_cat.exe
SET HEXDUMP=%DIR_TOOLS%\hexdump.exe

IF NOT EXIST %input_bin% (
ECHO Binary file %input_bin% does not exist!
GOTO eof
)

pushd %utilpath%

IF EXIST %TMP_DIR% DEL /Q %TMP_DIR%\*
IF NOT EXIST %TMP_DIR% mkdir %TMP_DIR%

IF EXIST %out_hashbin% DEL /Q %out_hashbin%
IF EXIST %out_padbin% DEL /Q %out_padbin%

SET padding=0xFF
SET appsize=65504 

ECHO binary file to be handled: %input_bin%

ECHO ########## Calculate padding size ############ 

SET /A padsize = %appsize%
ECHO "application size is %appsize%"
ECHO "Total size with padding is %padsize%" 

ECHO ########## Add padding to binary file: ############
ECHO size %padsize%, padding byte [%padding%]

%SREC% %input_bin% -binary -fill %padding% 0x0000 %padsize% -o %out_padbin% -binary

ECHO ########## Generate hash ############  
ECHO %OPENSSL% dgst -sha256 -binary %out_padbin% > %hashvalue%
%OPENSSL% dgst -sha256 -binary %out_padbin% > %hashvalue%
	ECHO FW HASH Value
	%HEXDUMP% %hashvalue%
	
ECHO ########## Generate bin + padding + hash ############  
COPY /B %out_padbin% + %hashvalue%  %out_hashbin%  >nul
COPY /B %out_hashbin% %out_toFlash% >nul

:eof
rem IF EXIST %TMP_DIR% DEL /Q %TMP_DIR%\*
endlocal
pause	