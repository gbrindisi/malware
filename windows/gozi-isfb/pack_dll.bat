del %2\client_p.dll
del %2\Client.bin

call %1\encrypts.bat %1 %2 client.dll

cd %1\cryptor
mpack %2\client.dll %2\client_p.dll
%1\appack.exe c %2\client_p.dll %2\Client.bin