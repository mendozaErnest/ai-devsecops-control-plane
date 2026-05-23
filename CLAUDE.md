# AI DevSecOps Control Plane — Instrucciones para Claude

## Contexto del proyecto

Repo: /home/zamaer/Documentos/codigo-general/AI-DevSecOps-Control-Plane
Conda env: devsecops-control-plane
Python: /home/zamaer/anaconda3/envs/devsecops-control-plane/bin/python3
Validacion: python3 -m compileall src && python3 -m pytest tests/ -v
Tests actuales: 42 passed — deben seguir pasando tras cualquier cambio.

## Reglas de trabajo

- Leer cada archivo antes de editarlo.
- No hacer git reset --hard.
- No tocar tests ni archivos fuera del scope del fix.
- Usar siempre el python del conda env para ejecutar scripts y tests.

## Al terminar cada tarea

Actualiza estos dos archivos para reflejar el estado real del repo:

### 1. docs/ai-current-project-context.md
- Marca como ✅ los items que acabas de implementar.
- Agrega cualquier bug nuevo encontrado en "Riesgos Conocidos".
- Actualiza la seccion "Proximos Pasos Recomendados".
- Actualiza el numero de tests en "Tests Actuales".

### 2. ROADMAP.md
- Mueve los items implementados de "Pendiente" a "Completo".
- Actualiza los porcentajes si corresponde.

Incluye ambos archivos en el commit final de la tarea.

Lee estos archivos antes de hacer cualquier cambio:
- docs/ai-current-project-context.md  ← estado actual del repo
- ROADMAP.md                          ← que sigue y que esta pendiente
