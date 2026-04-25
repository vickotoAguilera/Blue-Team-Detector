@echo off
echo Iniciando Simulador Ciberseguridad Blue Team...
echo [!] Abriendo Centro de Defensa (Puerto 3000)
start cmd /k "cd dashboard && npm run dev"

echo [!] Abriendo Agencia Objetivo (Puerto 3001)
start cmd /k "cd pagina_de_prueba && npm run dev -- -p 3001"

echo Ambientes inicializados con exito.
exit
