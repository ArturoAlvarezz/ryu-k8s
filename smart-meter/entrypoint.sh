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
# 2. Obtener IP via DHCP
#    -i eth0     : interfaz objetivo
#    -n          : salir con error si no obtiene lease en timeout
#    -q          : modo silencioso (quiet)
#    -t 10       : 10 intentos de descubrimiento
#    -T 3        : timeout de 3 segundos por intento
# ---------------------------------------------------------------------------
echo "[dhcp] Solicitando dirección IP via DHCP en eth0..."
MAX_RETRIES=10
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_RETRIES ]; do
    ATTEMPT=$((ATTEMPT + 1))
    echo "[dhcp] Intento $ATTEMPT/$MAX_RETRIES..."
    
    if udhcpc -i eth0 -n -q -t 5 -T 3 2>/dev/null; then
        echo "[dhcp] ¡Lease DHCP obtenido!"
        break
    fi
    
    if [ $ATTEMPT -eq $MAX_RETRIES ]; then
        echo "[dhcp] ADVERTENCIA: No se pudo obtener IP via DHCP después de $MAX_RETRIES intentos."
        echo "[dhcp] Continuando de todos modos (la app esperará IP internamente)..."
    else
        echo "[dhcp] Reintentando en 5 segundos..."
        sleep 5
    fi
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
