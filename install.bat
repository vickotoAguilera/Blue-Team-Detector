@echo off
title Blue Team Defense Center - Instalador
color 0A
cd /d "%~dp0"
echo =======================================================
echo  BLUE TEAM DEFENSE CENTER - SETUP SCRIPT
echo =======================================================
echo.
echo Directorio: %cd%
echo.
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    color 0C
    echo [ERROR] Node.js no detectado. Instala Node.js v18+ desde https://nodejs.org/
    pause
    exit /b
)
echo [OK] Node.js detectado.
echo.
echo Instalando dependencias del Dashboard...
cd /d "%~dp0dashboard"
call npm install
cd /d "%~dp0"
echo.
echo Instalando dependencias de la Pagina de Prueba...
cd /d "%~dp0pagina_de_prueba"
call npm install
cd /d "%~dp0"
echo.
if not exist "dashboard\.env.local" (
    echo GROQ_API_KEY=tu_clave_aqui > "dashboard\.env.local"
    echo [OK] Plantilla .env.local creada.
) else (
    echo [OK] .env.local ya existe.
)
echo.
echo =======================================================
echo  INSTALACION COMPLETADA
echo  Ejecuta start_all.bat para iniciar.
echo =======================================================
pause
