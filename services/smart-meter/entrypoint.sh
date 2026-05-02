#!/bin/sh
# =============================================================================
# entrypoint.sh — SDN Smart Meter Boot Script
# =============================================================================
# 1. Levanta la interfaz eth0
# 2. Solicita IP vía DHCP (udhcpc es parte de BusyBox/Alpine)
# 3. Lanza el servicio Python del medidor
# =============================================================================

set -e

echo "============================================================"
echo " SDN Smart Meter — Entrypoint"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. Configurar interfaz de red
# ---------------------------------------------------------------------------
echo "[net] Levantando interfaz eth0..."
ip link set eth0 up 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Obtener IP via DHCP.
#    Los guests pueden arrancar antes que el DaemonSet DHCP del nodo SDN.
#    Por eso no hay limite global de intentos: el contenedor sigue pidiendo
#    lease hasta que la red de control este lista, sin requerir reinicio manual.
# ---------------------------------------------------------------------------
echo "[dhcp] Solicitando dirección IP via DHCP en eth0..."
ATTEMPT=0
RETRY_INTERVAL="${DHCP_RETRY_INTERVAL:-5}"

while true; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "[dhcp] Intento $ATTEMPT..."
    
    if udhcpc -i eth0 -n -q -t 5 -T 3 2>/dev/null; then
        echo "[dhcp] ¡Lease DHCP obtenido!"
        break
    fi

    echo "[dhcp] DHCP aun no disponible; reintentando en ${RETRY_INTERVAL}s..."
    sleep "$RETRY_INTERVAL"
done

# ---------------------------------------------------------------------------
# 3. Mostrar configuración de red final
# ---------------------------------------------------------------------------
echo "[net] Configuración de red actual:"
ip addr show eth0 2>/dev/null || ip addr show

# ---------------------------------------------------------------------------
# 4. Lanzar el medidor
# ---------------------------------------------------------------------------
echo "[start] Iniciando SDN Smart Meter..."
exec python /app/app.py
