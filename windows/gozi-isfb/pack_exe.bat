del %1release\crm_p.exe

call %1\encrypts.bat %1 %2 crm.exe

cd %1cryptor
mpack %1release\crm.exe %1release\crm_p.exe crm.ico
