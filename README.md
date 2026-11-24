# NEXUS - Smart City Crime Intelligence Platform
Plain Java 17 (built-in HttpServer + JDBC) + SQL (H2) + HTML + CSS + JavaScript. No frameworks.

## Setup
1. Install the Java JDK 17 or newer (the JDK, not only the JRE - it must include `javac`).
2. Download the H2 database driver (one file) and put it in the `lib/` folder:
   https://repo1.maven.org/maven2/com/h2database/h2/2.2.224/h2-2.2.224.jar
3. Run `run.bat` (Windows) or `./run.sh` (Mac/Linux).
4. Open http://localhost:8080
   - admin / Nexus@123 (full access + audit log), officer / Officer@123 (add, resolve, dispatch), viewer / Viewer@123 (read-only)
   - Change these passwords before any real use.

## Files
- src/Server.java  - web server, REST API, JDBC code, PBKDF2 password hashing
- schema.sql       - SQL tables (users, incidents, units)
- public/          - index.html (login), dashboard.html, nexus.css
- data/            - created automatically (the SQL database file)

## Use MySQL instead
Put mysql-connector-j.jar in lib/, create a database named nexus, change DB_URL/DB_USER/DB_PASS in Server.java.
Replace H2's DATEADD(...) calls with MySQL's DATE_ADD / TIMESTAMPADD.

## Advanced features
- Roles (SUPER_ADMIN / OFFICER / VIEWER) enforced on the server, 8-hour sessions, logout, login lockout (5 failures = 5 min)
- Audit log table + admin-only Audit Log page
- Live updates with Server-Sent Events (new incidents and dispatches appear instantly); SIMULATE=true in Server.java adds a demo incident every 60s
- Live map (canvas heatmap, zone risk, patrol unit positions) from lat/lng stored in SQL
- 24h trend chart + 6h forecast (linear regression in Java), peak-hour per zone from SQL
- Auto-dispatch: picks the nearest free unit using haversine distance

## Unique features
- **Smart Patrol Route:** Patrol Units tab -> "SMART ROUTE (3)". One unit covers up to 3 active incidents using the Nearest-Neighbour algorithm
  (always go to the closest unvisited incident). Shows total km vs separate trips, and draws the route on the live map.
- **Citizen SOS:** public page `public/sos.html` (link on the login page). No login. Browser GPS -> incident type SOS is created ->
  nearest free unit is auto-dispatched -> operators get an instant red alert + beep. If GPS is outside Coimbatore the citizen picks an area.
  Abuse protection: max 3 SOS per IP per 10 minutes. Demo only - real emergencies: call 112.
