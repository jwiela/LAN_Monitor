#!/bin/bash
# Skrypt instalacji InfluxDB i Grafana na Raspberry Pi
# Wymaga sudo

set -e

echo "🚀 Instalacja InfluxDB i Grafana dla LAN Monitor"
echo "================================================"
echo ""

# Sprawdź czy działa jako root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Uruchom skrypt z sudo: sudo bash install_monitoring.sh"
    exit 1
fi

# Aktualizuj system
echo "📦 Aktualizacja systemu..."
apt-get update

# Instalacja InfluxDB
echo ""
echo "📊 Instalacja InfluxDB 2.x..."
if ! command -v influx &> /dev/null; then
    # Dodaj klucz GPG i repozytorium
    wget -q https://repos.influxdata.com/influxdata-archive_compat.key
    echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
    echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list
    
    apt-get update
    apt-get install -y influxdb2 influxdb2-cli
    
    # Uruchom InfluxDB
    systemctl enable influxdb
    systemctl start influxdb
    
    echo "✅ InfluxDB zainstalowany"
else
    echo "✅ InfluxDB już zainstalowany"
fi

# Instalacja Grafana
echo ""
echo "📈 Instalacja Grafana..."
if ! command -v grafana-server &> /dev/null; then
    # Dodaj klucz GPG i repozytorium Grafana
    wget -q -O - https://packages.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/grafana.gpg] https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
    
    apt-get update
    apt-get install -y grafana
    
    # Uruchom Grafana
    systemctl enable grafana-server
    systemctl start grafana-server
    
    echo "✅ Grafana zainstalowana"
else
    echo "✅ Grafana już zainstalowana"
fi

echo ""
echo "================================================"
echo "✅ Instalacja zakończona!"
echo ""
echo "Następne kroki:"
echo ""
echo "1. InfluxDB (http://localhost:8086):"
echo "   - Otwórz w przeglądarce: http://$(hostname -I | awk '{print $1}'):8086"
echo "   - Wykonaj setup (username, password, organization: lan_monitor, bucket: network_traffic)"
echo "   - Skopiuj token i dodaj do .env jako INFLUXDB_TOKEN"
echo ""
echo "2. Grafana (http://localhost:3000):"
echo "   - Otwórz w przeglądarce: http://$(hostname -I | awk '{print $1}'):3000"
echo "   - Domyślne logowanie: admin / admin"
echo "   - Dodaj InfluxDB jako źródło danych (Data Sources)"
echo "   - Zaimportuj dashboard z pliku grafana_dashboard.json"
echo ""
echo "3. Zaktualizuj plik .env:"
echo "   INFLUXDB_ENABLED=true"
echo "   INFLUXDB_URL=http://localhost:8086"
echo "   INFLUXDB_TOKEN=<twój_token>"
echo "   INFLUXDB_ORG=lan_monitor"
echo "   INFLUXDB_BUCKET=network_traffic"
echo "   GRAFANA_ENABLED=true"
echo "   GRAFANA_URL=http://localhost:3000"
echo ""
echo "4. Uruchom ponownie aplikację: sudo .venv/bin/python run.py"
echo ""
