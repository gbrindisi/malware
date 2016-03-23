@echo off
echo #define g_Version %1 > id.h
msbuild isfb.sln /t:build /p:Configuration=Release /p:Platform=x64 
msbuild isfb.sln /t:build /p:Configuration=Release
if exist release\%1.exe. del release\%1.exe 
ren release\crm_p.exe %1.exe