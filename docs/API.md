# Smonitor REST API & SQLite Integration Reference

Diese Referenz beschreibt alle HTTP-Endpunkte der REST-API im `--daemon`-Modus sowie direkte SQLite-Abfragen für externe Systeme (z. B. Node-RED, Grafana, Cron-Skripte).

---

## Authentifizierung & CORS

- **Optionaler API-Token (`--api-token`)**:
  - Wenn `--api-token` gesetzt ist, erfordern alle `/api/v1/*`-Endpunkte ein Token über einen der beiden Header:
    - `Authorization: Bearer <token>`
    - `X-API-Key: <token>`
  - Der Token-Vergleich erfolgt zeitkonstant (`subtle.ConstantTimeCompare`).
  - `GET /healthz` und `OPTIONS` (CORS-Preflight) sind immer ohne Token erreichbar.
- **CORS**: Alle Antworten setzen `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: GET, POST, OPTIONS` und `Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key`.

---

## Endpunkte im Detail

### 1. Health-Check
`GET /healthz`

```bash
curl -s http://127.0.0.1:8080/healthz
```

**Antwort (`200 OK`):**
```json
{
  "status": "ok"
}
```

---

### 2. Monitoring-Metriken
`GET /api/v1/metrics`

Liefert aggregierte Zähler aus SQLite sowie Laufzeitdaten des letzten Scans im Daemon.

```bash
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/v1/metrics
```

**Antwort (`200 OK`):**
```json
{
  "total_hosts": 12,
  "online_hosts": 10,
  "offline_hosts": 2,
  "new_hosts_24h": 1,
  "last_scan_duration_ms": 482,
  "last_scan_timestamp": "2026-11-25T10:40:00Z"
}
```

---

### 3. Alle Hosts abfragen
`GET /api/v1/hosts`

Optionale Query-Parameter:
- `?online=true` oder `?online=1` — nur aktuell erreichbare Hosts
- `?online=false` oder `?online=0` — nur Offline-Hosts (inkl. `last_seen` als letzter erreichbarer Zeitpunkt)

```bash
curl -s -H "X-API-Key: <token>" "http://127.0.0.1:8080/api/v1/hosts?online=false"
```

**Antwort (`200 OK`):**
```json
[
  {
    "ip_address": "192.168.1.42",
    "hostname": "shelly-plug.local",
    "notes": "Wohnzimmer Stehlampe",
    "is_online": false,
    "rtt_ms": 2.14,
    "first_seen": "2026-11-20T08:15:00Z",
    "last_seen": "2026-11-25T09:30:12Z",
    "last_offline": "2026-11-25T09:32:12Z",
    "hop_count": 2,
    "last_route": [
      { "ttl": 1, "ip": "192.168.1.1", "rtt_ms": 0.45 },
      { "ttl": 2, "ip": "192.168.1.42", "rtt_ms": 2.14 }
    ]
  }
]
```

---

### 4. Einzelnen Host abfragen
`GET /api/v1/hosts/{ip}`

Erfordert eine gültige IPv4-Adresse im Pfad.

```bash
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/v1/hosts/192.168.1.42
```

**Statuscodes:**
- `200 OK` — Host-Objekt
- `400 Bad Request` — ungültige IPv4-Adresse (z. B. IPv6 oder Text)
- `404 Not Found` — IP nicht in der Datenbank vorhanden

---

### 5. Notiz zu einem Host setzen
`POST /api/v1/hosts/{ip}/notes`

Erfordert einen gültigen JSON-Body (maximal `64 KiB`) mit Feld `"notes"`.

```bash
curl -s -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"notes":"NAS Server Keller"}' \
  http://127.0.0.1:8080/api/v1/hosts/192.168.1.100/notes
```

**Antwort (`200 OK`):**
```json
{
  "message": "notes updated successfully",
  "ip": "192.168.1.100",
  "notes": "NAS Server Keller"
}
```

**Fehler (`400 Bad Request`):** Ungültige IPv4-Adresse, fehlender/fehlerhafter JSON-Body oder Host existiert nicht in der Datenbank.

---

### 6. Ereignisprotokoll (Online/Offline-Historie)
`GET /api/v1/events`

Query-Parameter:
- `?limit=50` — Anzahl der neuesten Events (Standard: `50`, Maximum: `1000`).

```bash
curl -s -H "Authorization: Bearer <token>" "http://127.0.0.1:8080/api/v1/events?limit=20"
```

**Antwort (`200 OK`):**
```json
[
  {
    "id": 14,
    "ip_address": "192.168.1.42",
    "event_type": "OFFLINE",
    "details": "Host unreachable (last reachable: 2026-11-25T09:30:12Z)",
    "timestamp": "2026-11-25T09:32:12Z"
  }
]
```

---

### 7. Sofortigen Scan anstoßen
`POST /api/v1/scan`

Lädt `ranges.json` neu, führt Ping-Sweep und Traceroute aus und gibt die aktualisierten Metriken zurück.

```bash
curl -s -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/v1/scan
```

---

### 8. Live-Traceroute für eine IPv4-Adresse ausführen
`POST /api/v1/traceroute/{ip}`

Führt einen sofortigen ICMP-Traceroute zur angegebenen IPv4-Adresse aus. Falls die IP bereits in `hosts` existiert, wird `last_route` und `hop_count` in SQLite aktualisiert.

```bash
curl -s -X POST -H "Authorization: Bearer <token>" http://127.0.0.1:8080/api/v1/traceroute/192.168.1.1
```

**Antwort (`200 OK`):**
```json
{
  "ip": "192.168.1.1",
  "hop_count": 1,
  "hops": [
    { "ttl": 1, "ip": "192.168.1.1", "rtt_ms": 0.42 }
  ]
}
```

---

## Direkte SQLite-Anbindung (WAL Read-Only)

Da `smonitor` SQLite im `WAL`-Modus (`smonitor.db`, `smonitor.db-wal`, `smonitor.db-shm`) betreibt, können externe Prozesse gleichzeitig lesend zugreifen, ohne den Scanner zu blockieren:

```sql
-- Alle Offline-Hosts mit letztem erreichbarem Zeitpunkt und letzter Offline-Zeit
SELECT
    ip_address,
    hostname,
    notes,
    last_seen    AS last_reachable_utc,
    last_offline AS offline_since_utc
FROM hosts
WHERE is_online = 0
ORDER BY last_offline DESC;

-- Traceroute-Hops eines Hosts direkt in SQLite auspacken (SQLite JSON1)
SELECT
    h.ip_address,
    json_extract(hop.value, '$.ttl')     AS hop_ttl,
    json_extract(hop.value, '$.ip')      AS hop_ip,
    json_extract(hop.value, '$.rtt_ms')  AS hop_rtt_ms,
    json_extract(hop.value, '$.timeout') AS hop_timeout
FROM hosts h,
     json_each(h.last_route) AS hop
WHERE h.ip_address = '192.168.1.42'
ORDER BY hop_ttl ASC;
```
