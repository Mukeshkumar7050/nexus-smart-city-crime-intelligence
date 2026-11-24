import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** NEXUS - plain Java web server + JDBC (H2 SQL database). No frameworks. */
public class Server {
    static final String DB_URL = "jdbc:h2:./data/nexus";   // change to jdbc:mysql://localhost:3306/nexus for MySQL
    static final String DB_USER = "sa", DB_PASS = "";
    static final List<String> ZONES = List.of("Gandhipuram", "RS Puram", "Peelamedu", "Town Hall", "Saibaba Colony");
    static final List<String> TYPES = List.of("Theft", "Assault", "Burglary", "Vandalism");
    static final Set<String> STATUSES = Set.of("Active", "Investigating", "Resolved");
    record Session(String user, String role, long exp) { }
    static final Map<String, Session> TOKENS = new ConcurrentHashMap<>();
    static final Map<String, long[]> FAILS = new ConcurrentHashMap<>();
    static final List<OutputStream> CLIENTS = new CopyOnWriteArrayList<>();   // live (SSE) subscribers
    static final boolean SIMULATE = true;                                     // creates a demo incident every 60s
    static final Map<String, double[]> CENTERS = new LinkedHashMap<>();
    static {
        CENTERS.put("Gandhipuram", new double[]{11.0183, 76.9725});
        CENTERS.put("RS Puram", new double[]{11.0089, 76.9500});
        CENTERS.put("Peelamedu", new double[]{11.0243, 77.0044});
        CENTERS.put("Town Hall", new double[]{10.9925, 76.9614});
        CENTERS.put("Saibaba Colony", new double[]{11.0262, 76.9437});
    }
    static final Path WEB_ROOT = Paths.get("public").toAbsolutePath().normalize();

    // ---------------------------------------------------------------- main
    public static void main(String[] args) throws Exception {
        initDb();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/", Server::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        startBackground();
        System.out.println("NEXUS running at http://localhost:8080   (admin / Nexus@123, officer / Officer@123, viewer / Viewer@123)");
    }

    // ------------------------------------------------------------ database
    static Connection conn() throws SQLException { return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS); }

    static List<Map<String, Object>> query(String sql, Object... args) throws SQLException {
        try (Connection c = conn(); PreparedStatement p = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) p.setObject(i + 1, args[i]);
            try (ResultSet rs = p.executeQuery()) {
                ResultSetMetaData md = rs.getMetaData();
                List<Map<String, Object>> out = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    for (int i = 1; i <= md.getColumnCount(); i++) m.put(md.getColumnLabel(i).toLowerCase(), rs.getObject(i));
                    out.add(m);
                }
                return out;
            }
        }
    }

    static int update(String sql, Object... args) throws SQLException {
        try (Connection c = conn(); PreparedStatement p = c.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) p.setObject(i + 1, args[i]);
            return p.executeUpdate();
        }
    }

    static int count(String sql, Object... args) throws SQLException {
        return ((Number) query(sql, args).get(0).values().iterator().next()).intValue();
    }

    static void initDb() throws Exception {
        for (String stmt : Files.readString(Paths.get("schema.sql")).split(";"))
            if (!stmt.isBlank()) update(stmt);

        String[][] us = {{"admin", "Nexus@123", "SUPER_ADMIN"}, {"officer", "Officer@123", "OFFICER"}, {"viewer", "Viewer@123", "VIEWER"}};
        for (String[] usr : us)
            if (count("select count(*) from users where username = ?", usr[0]) == 0)
                update("insert into users(username,password_hash,role) values(?,?,?)", usr[0], hashNew(usr[1]), usr[2]);

        if (count("select count(*) from incidents") == 0) {
            Random r = new Random(7);
            String[] st = {"Active", "Active", "Investigating", "Resolved", "Resolved"};
            int[] weight = {5, 3, 2, 2, 1};                       // Gandhipuram is the busiest zone
            for (int i = 0; i < 60; i++) {
                int z = 0, roll = r.nextInt(13), acc = 0;
                for (; z < 4; z++) { acc += weight[z]; if (roll < acc) break; }
                update("insert into incidents(type,location,zone,description,status,created_at) values(?,?,?,?,?,DATEADD('MINUTE',?,CURRENT_TIMESTAMP))",
                        TYPES.get(r.nextInt(4)), ZONES.get(z) + " Main Road", ZONES.get(z), "Auto-seeded sample incident", st[r.nextInt(5)], -r.nextInt(2000));
            }
        }
        if (count("select count(*) from units") == 0) {
            String[][] u = {{"P-01", "R. Sharma", "Gandhipuram", "ON DUTY"}, {"P-03", "M. Kumar", "Town Hall", "PATROL"},
                    {"P-05", "K. Singh", "Saibaba Colony", "ON DUTY"}, {"P-07", "A. Verma", "RS Puram", "ON DUTY"},
                    {"P-12", "S. Patel", "Peelamedu", "PATROL"}};
            for (String[] a : u) update("insert into units(code,officer,zone,status) values(?,?,?,?)", (Object[]) a);
        }
        for (Map.Entry<String, double[]> e : CENTERS.entrySet()) {   // give old/new rows map coordinates
            double[] c = e.getValue();
            update("update incidents set lat = ? + (RAND() - 0.5) * 0.012, lng = ? + (RAND() - 0.5) * 0.012 where lat is null and zone = ?", c[0], c[1], e.getKey());
            update("update units set lat = ?, lng = ? where lat is null and zone = ?", c[0], c[1], e.getKey());
        }
    }

    // ------------------------------------------------------------ passwords (PBKDF2, built into the JDK)
    static String pbkdf2(String pw, byte[] salt) throws Exception {
        byte[] h = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 120_000, 256)).getEncoded();
        return HexFormat.of().formatHex(h);
    }
    static String hashNew(String pw) throws Exception {
        byte[] salt = new byte[16]; new SecureRandom().nextBytes(salt);
        return HexFormat.of().formatHex(salt) + ":" + pbkdf2(pw, salt);
    }
    static boolean verify(String pw, String stored) throws Exception {
        String[] p = stored.split(":");
        return MessageDigest.isEqual(pbkdf2(pw, HexFormat.of().parseHex(p[0])).getBytes(), p[1].getBytes());
    }

    // ------------------------------------------------------------ tiny JSON helpers
    static String json(Object o) {
        if (o == null) return "null";
        if (o instanceof Number || o instanceof Boolean) return o.toString();
        if (o instanceof Map<?, ?> m) {
            StringJoiner j = new StringJoiner(",", "{", "}");
            m.forEach((k, v) -> j.add(json(String.valueOf(k)) + ":" + json(v)));
            return j.toString();
        }
        if (o instanceof Collection<?> c) {
            StringJoiner j = new StringJoiner(",", "[", "]");
            for (Object x : c) j.add(json(x));
            return j.toString();
        }
        String s = (o instanceof Timestamp t) ? t.toLocalDateTime().toString() : o.toString();
        StringBuilder b = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (ch < 0x20) b.append(String.format("\\u%04x", (int) ch)); else b.append(ch); }
            }
        }
        return b.append('"').toString();
    }

    /** Parses a flat JSON object of string values, e.g. {"username":"admin","password":"x"}. */
    static Map<String, String> body(HttpExchange x) throws IOException {
        String s = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> m = new HashMap<>();
        Matcher mt = Pattern.compile("\"(\\w+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(s);
        while (mt.find()) m.put(mt.group(1), unescape(mt.group(2)));
        return m;
    }
    static String unescape(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) { b.append(c); continue; }
            char n = s.charAt(++i);
            switch (n) {
                case 'n' -> b.append('\n'); case 't' -> b.append('\t'); case 'r' -> b.append('\r');
                case 'u' -> { b.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; }
                default -> b.append(n);
            }
        }
        return b.toString();
    }
    static Map<String, String> params(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null) return m;
        for (String kv : raw.split("&")) {
            String[] p = kv.split("=", 2);
            m.put(URLDecoder.decode(p[0], StandardCharsets.UTF_8), p.length > 1 ? URLDecoder.decode(p[1], StandardCharsets.UTF_8) : "");
        }
        return m;
    }

    // ------------------------------------------------------------ http plumbing
    static void send(HttpExchange x, int code, String type, byte[] data) throws IOException {
        x.getResponseHeaders().set("Content-Type", type);
        x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        x.sendResponseHeaders(code, data.length == 0 ? -1 : data.length);
        if (data.length > 0) try (OutputStream o = x.getResponseBody()) { o.write(data); }
        x.close();
    }
    static void sendJson(HttpExchange x, int code, Object o) throws IOException {
        send(x, code, "application/json; charset=utf-8", json(o).getBytes(StandardCharsets.UTF_8));
    }

    static void handle(HttpExchange x) {
        try {
            String path = x.getRequestURI().getPath();
            if (path.startsWith("/api/")) api(x, path.substring(4), x.getRequestMethod());
            else serveFile(x, path);
        } catch (Exception e) {
            e.printStackTrace();
            try { sendJson(x, 500, Map.of("error", "Server error")); } catch (Exception ignored) { }
        }
    }

    static void serveFile(HttpExchange x, String path) throws IOException {
        Path f = WEB_ROOT.resolve("." + (path.equals("/") ? "/index.html" : path)).normalize();
        if (!f.startsWith(WEB_ROOT) || !Files.isRegularFile(f)) { send(x, 404, "text/plain", "Not found".getBytes()); return; }
        String n = f.getFileName().toString();
        String type = n.endsWith(".html") ? "text/html; charset=utf-8" : n.endsWith(".css") ? "text/css; charset=utf-8"
                : n.endsWith(".js") ? "text/javascript; charset=utf-8" : "application/octet-stream";
        send(x, 200, type, Files.readAllBytes(f));
    }

    // ------------------------------------------------------------ audit, live push, background jobs
    static String cut(String s, int n) { return s.length() > n ? s.substring(0, n) : s; }

    static void audit(String user, String action, String detail) {
        try { update("insert into audit_log(username,action,detail) values(?,?,?)", cut(user, 50), action, cut(detail, 200)); }
        catch (SQLException e) { e.printStackTrace(); }
    }

    static void pushRaw(byte[] d) {
        for (OutputStream o : CLIENTS) synchronized (o) {
            try { o.write(d); o.flush(); } catch (IOException e) { CLIENTS.remove(o); }
        }
    }
    static void broadcast(Object ev) { pushRaw(("data: " + json(ev) + "\n\n").getBytes(StandardCharsets.UTF_8)); }

    static long addIncident(String type, String loc, String zone, String desc, String user, boolean sim) throws SQLException {
        double[] c = CENTERS.get(zone); Random r = new Random();
        update("insert into incidents(type,location,zone,description,lat,lng) values(?,?,?,?,?,?)", type, loc, zone, desc,
                c[0] + (r.nextDouble() - 0.5) * 0.012, c[1] + (r.nextDouble() - 0.5) * 0.012);
        long id = ((Number) query("select max(id) m from incidents").get(0).get("m")).longValue();
        audit(user, sim ? "SIMULATED_INCIDENT" : "NEW_INCIDENT", "incident " + id + " " + type + " @ " + zone);
        broadcast(Map.of("event", "incident", "id", id, "type", type, "zone", zone, "location", loc, "simulated", sim));
        return id;
    }

    static double km(double la1, double ln1, double la2, double ln2) {      // haversine distance
        double dLa = Math.toRadians(la2 - la1), dLn = Math.toRadians(ln2 - ln1);
        double a = Math.pow(Math.sin(dLa / 2), 2) + Math.cos(Math.toRadians(la1)) * Math.cos(Math.toRadians(la2)) * Math.pow(Math.sin(dLn / 2), 2);
        return 12742 * Math.asin(Math.sqrt(a));
    }

    static void startBackground() {
        ScheduledExecutorService ex = Executors.newScheduledThreadPool(1);
        ex.scheduleAtFixedRate(() -> {
            pushRaw(": ping\n\n".getBytes());
            TOKENS.values().removeIf(s -> s.exp() < System.currentTimeMillis());
        }, 15, 15, TimeUnit.SECONDS);
        if (SIMULATE) ex.scheduleAtFixedRate(() -> {
            try {
                Random r = new Random(); String z = ZONES.get(r.nextInt(5));
                addIncident(TYPES.get(r.nextInt(4)), z + " (simulated)", z, "Simulated live incident", "system", true);
            } catch (Exception e) { e.printStackTrace(); }
        }, 30, 60, TimeUnit.SECONDS);
    }

    // ------------------------------------------------------------ SOS + smart route helpers
    static final Map<String, Deque<Long>> SOS_LOG = new ConcurrentHashMap<>();
    static double num(Object o) { return ((Number) o).doubleValue(); }
    static double round1(double v) { return Math.round(v * 10) / 10.0; }

    /** Sends the nearest free unit to an incident. Returns null when every unit is busy. */
    static Map<String, Object> dispatchNearest(long id, double la, double ln, String zone, String user) throws SQLException {
        Map<String, Object> best = null; double bd = 1e9;
        for (var u : query("select * from units where status <> 'RESPONDING'")) {
            if (u.get("lat") == null) continue;
            double d = km(la, ln, num(u.get("lat")), num(u.get("lng")));
            if (d < bd) { bd = d; best = u; }
        }
        if (best == null) return null;
        update("update units set status = 'RESPONDING', zone = ?, lat = ?, lng = ? where id = ?", zone, la, ln, best.get("id"));
        update("update incidents set status = 'Investigating' where id = ?", id);
        audit(user, "AUTO_DISPATCH", "unit " + best.get("code") + " -> incident " + id);
        broadcast(Map.of("event", "dispatch", "unit", best.get("code"), "zone", zone));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("unit", best.get("code")); out.put("distanceKm", round1(bd));
        return out;
    }

    /** PUBLIC endpoint (no login): a citizen presses SOS -> incident is created -> nearest unit is dispatched. */
    static void sos(HttpExchange x) throws Exception {
        String ip = x.getRemoteAddress().getAddress().getHostAddress();
        long now = System.currentTimeMillis();
        Deque<Long> dq = SOS_LOG.computeIfAbsent(ip, k -> new ConcurrentLinkedDeque<>());
        while (!dq.isEmpty() && dq.peekFirst() < now - 600_000) dq.pollFirst();
        if (dq.size() >= 3) { sendJson(x, 429, Map.of("error", "Too many SOS requests. Please call 112 directly.")); return; }
        Map<String, String> b = body(x);
        double lat = Double.NaN, lng = Double.NaN;
        try { lat = Double.parseDouble(b.getOrDefault("lat", "")); lng = Double.parseDouble(b.getOrDefault("lng", "")); }
        catch (NumberFormatException e) { lat = Double.NaN; }
        String zone = null; double bd = 1e9;
        if (!Double.isNaN(lat) && !Double.isNaN(lng))
            for (Map.Entry<String, double[]> e : CENTERS.entrySet()) {
                double d = km(lat, lng, e.getValue()[0], e.getValue()[1]);
                if (d < bd) { bd = d; zone = e.getKey(); }
            }
        if (zone == null || bd > 25) {                       // GPS missing or outside the city -> use the area the citizen picked
            zone = b.getOrDefault("zone", "");
            if (!ZONES.contains(zone)) { sendJson(x, 400, Map.of("error", "Location is outside the service area. Please choose your area.")); return; }
            lat = CENTERS.get(zone)[0]; lng = CENTERS.get(zone)[1];
        }
        dq.addLast(now);
        String desc = "SOS | phone: " + cut(b.getOrDefault("phone", "").replaceAll("[^0-9+ ]", ""), 20) + " | " + cut(b.getOrDefault("message", ""), 150);
        update("insert into incidents(type,location,zone,description,lat,lng) values(?,?,?,?,?,?)", "SOS",
                "Citizen SOS (" + String.format(Locale.ROOT, "%.4f, %.4f", lat, lng) + ")", zone, desc, lat, lng);
        long id = ((Number) query("select max(id) m from incidents").get(0).get("m")).longValue();
        audit("citizen", "SOS", "incident " + id + " @ " + zone);
        Map<String, Object> disp = dispatchNearest(id, lat, lng, zone, "system");
        broadcast(Map.of("event", "incident", "id", id, "type", "SOS", "zone", zone, "location", "Citizen SOS", "simulated", false, "sos", true));
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("ok", true); res.put("id", id); res.put("zone", zone);
        res.put("unit", disp == null ? null : disp.get("unit")); res.put("distanceKm", disp == null ? null : disp.get("distanceKm"));
        sendJson(x, 200, res);
    }

    // ------------------------------------------------------------ REST API
    static void api(HttpExchange x, String path, String m) throws Exception {
        if (path.equals("/login") && m.equals("POST")) {
            Map<String, String> b = body(x);
            String un = cut(b.getOrDefault("username", "").toLowerCase(), 50);
            long[] f = FAILS.computeIfAbsent(un, k -> new long[2]);      // [failed attempts, locked until]
            if (f[1] > System.currentTimeMillis()) { sendJson(x, 429, Map.of("error", "Too many attempts. Try again in 5 minutes.")); return; }
            List<Map<String, Object>> u = query("select * from users where lower(username) = ?", un);
            if (u.isEmpty() || !verify(b.getOrDefault("password", ""), (String) u.get(0).get("password_hash"))) {
                if (++f[0] >= 5) { f[1] = System.currentTimeMillis() + 300_000; f[0] = 0; }
                audit(un, "LOGIN_FAILED", "");
                sendJson(x, 401, Map.of("error", "Invalid credentials. Access denied.")); return;
            }
            f[0] = 0;
            String token = UUID.randomUUID().toString(), role = (String) u.get(0).get("role"), name = (String) u.get(0).get("username");
            TOKENS.put(token, new Session(name, role, System.currentTimeMillis() + 8 * 3600_000L));
            audit(name, "LOGIN", "");
            sendJson(x, 200, Map.of("token", token, "user", name, "role", role));
            return;
        }
        if (path.equals("/sos") && m.equals("POST")) { sos(x); return; }               // public, no login
        String tk = x.getRequestHeaders().getFirst("X-Auth-Token");
        Session ses = tk == null ? null : TOKENS.get(tk);
        if (ses == null || ses.exp() < System.currentTimeMillis()) { sendJson(x, 401, Map.of("error", "Unauthorized")); return; }
        if (!m.equals("GET") && !path.equals("/logout") && ses.role().equals("VIEWER")) { sendJson(x, 403, Map.of("error", "Read-only account")); return; }

        if (path.equals("/stats")) {
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("total", count("select count(*) from incidents"));
            s.put("active", count("select count(*) from incidents where status <> 'Resolved'"));
            s.put("last24h", count("select count(*) from incidents where created_at > DATEADD('HOUR',-24,CURRENT_TIMESTAMP)"));
            s.put("unitsOnline", count("select count(*) from units"));
            s.put("byType", query("select type, count(*) c from incidents group by type order by c desc"));
            s.put("byZone", query("select zone, count(*) c, sum(case when status <> 'Resolved' then 1 else 0 end) active from incidents group by zone order by c desc"));
            sendJson(x, 200, s);

        } else if (path.equals("/incidents") && m.equals("GET")) {
            Map<String, String> q = params(x.getRequestURI().getRawQuery());
            String like = "%" + q.getOrDefault("q", "").toLowerCase() + "%", type = q.getOrDefault("type", "");
            sendJson(x, 200, query("select * from incidents where (lower(location) like ? or lower(zone) like ?) and (? = '' or type = ?) order by id desc limit 200",
                    like, like, type, type));

        } else if (path.equals("/incidents") && m.equals("POST")) {
            Map<String, String> b = body(x);
            String type = b.getOrDefault("type", ""), loc = b.getOrDefault("location", "").trim(), zone = b.getOrDefault("zone", ""), d = b.getOrDefault("description", "");
            if (!TYPES.contains(type) || loc.isEmpty() || loc.length() > 120 || !ZONES.contains(zone)) {
                sendJson(x, 400, Map.of("error", "Invalid incident data")); return;
            }
            addIncident(type, loc, zone, d.length() > 500 ? d.substring(0, 500) : d, ses.user(), false);
            sendJson(x, 200, Map.of("ok", true));

        } else if (path.matches("/incidents/\\d+/status") && m.equals("PUT")) {
            String s = body(x).getOrDefault("status", "");
            if (!STATUSES.contains(s)) { sendJson(x, 400, Map.of("error", "Invalid status")); return; }
            long id = Long.parseLong(path.split("/")[2]);
            update("update incidents set status = ? where id = ?", s, id);
            audit(ses.user(), "STATUS", "incident " + id + " -> " + s);
            if (s.equals("Resolved")) update("update units set status = 'ON DUTY' where id = (select id from units where status = 'RESPONDING' and zone = (select zone from incidents where id = ?) limit 1)", id);
            sendJson(x, 200, Map.of("ok", true));

        } else if (path.equals("/predictions")) {
            List<Map<String, Object>> rows = query("""
                select zone,
                  sum(case when status <> 'Resolved' then 1 else 0 end) active,
                  sum(case when created_at > DATEADD('HOUR',-24,CURRENT_TIMESTAMP) then 1 else 0 end) recent
                from incidents group by zone""");
            for (Map<String, Object> r : rows) {
                int risk = Math.min(100, ((Number) r.get("active")).intValue() * 5 + ((Number) r.get("recent")).intValue() * 3);
                r.put("risk", risk);
                r.put("level", risk >= 70 ? "HIGH" : risk >= 40 ? "MEDIUM" : "LOW");
                r.put("unitsNeeded", risk / 25 + 1);
                var pk = query("select HOUR(created_at) hr, count(*) c from incidents where zone = ? group by HOUR(created_at) order by c desc limit 1", r.get("zone"));
                r.put("peakHour", pk.isEmpty() ? null : pk.get(0).get("hr"));
            }
            rows.sort((a, b) -> (int) b.get("risk") - (int) a.get("risk"));
            sendJson(x, 200, rows);

        } else if (path.equals("/units")) {
            sendJson(x, 200, query("select * from units order by code"));

        } else if (path.matches("/units/\\d+/dispatch") && m.equals("POST")) {
            String zone = body(x).getOrDefault("zone", "");
            if (!ZONES.contains(zone)) { sendJson(x, 400, Map.of("error", "Unknown zone")); return; }
            double[] c = CENTERS.get(zone);
            update("update units set status = 'RESPONDING', zone = ?, lat = ?, lng = ? where id = ?", zone, c[0], c[1], Long.parseLong(path.split("/")[2]));
            audit(ses.user(), "DISPATCH", "unit " + path.split("/")[2] + " -> " + zone);
            sendJson(x, 200, Map.of("ok", true));

        } else if (path.matches("/incidents/\\d+/dispatch") && m.equals("POST")) {   // nearest free unit
            long id = Long.parseLong(path.split("/")[2]);
            var inc = query("select * from incidents where id = ?", id);
            if (inc.isEmpty() || inc.get(0).get("lat") == null) { sendJson(x, 404, Map.of("error", "Incident not found")); return; }
            double la = ((Number) inc.get(0).get("lat")).doubleValue(), ln = ((Number) inc.get(0).get("lng")).doubleValue(), bd = 1e9;
            Map<String, Object> best = null;
            for (var u : query("select * from units where status <> 'RESPONDING'")) {
                if (u.get("lat") == null) continue;
                double d = km(la, ln, ((Number) u.get("lat")).doubleValue(), ((Number) u.get("lng")).doubleValue());
                if (d < bd) { bd = d; best = u; }
            }
            if (best == null) { sendJson(x, 409, Map.of("error", "No available units")); return; }
            update("update units set status = 'RESPONDING', zone = ?, lat = ?, lng = ? where id = ?", inc.get(0).get("zone"), la, ln, best.get("id"));
            update("update incidents set status = 'Investigating' where id = ?", id);
            audit(ses.user(), "AUTO_DISPATCH", "unit " + best.get("code") + " -> incident " + id);
            broadcast(Map.of("event", "dispatch", "unit", best.get("code"), "zone", inc.get(0).get("zone")));
            sendJson(x, 200, Map.of("ok", true, "unit", best.get("code"), "distanceKm", Math.round(bd * 10) / 10.0));

        } else if (path.equals("/trend")) {                                          // 24h series + linear-regression forecast
            double[] h = new double[24];
            for (var r : query("select DATEDIFF('HOUR', created_at, CURRENT_TIMESTAMP) h, count(*) c from incidents where created_at > DATEADD('HOUR',-24,CURRENT_TIMESTAMP) group by DATEDIFF('HOUR', created_at, CURRENT_TIMESTAMP)")) {
                int i = ((Number) r.get("h")).intValue();
                if (i >= 0 && i < 24) h[23 - i] = ((Number) r.get("c")).doubleValue();
            }
            double n = 24, sx = 0, sy = 0, sxy = 0, sxx = 0;
            for (int i = 0; i < 24; i++) { sx += i; sy += h[i]; sxy += i * h[i]; sxx += (double) i * i; }
            double slope = (n * sxy - sx * sy) / (n * sxx - sx * sx), icpt = (sy - slope * sx) / n;
            List<Double> fc = new ArrayList<>();
            for (int i = 24; i < 30; i++) fc.add(Math.max(0, Math.round((icpt + slope * i) * 10) / 10.0));
            sendJson(x, 200, Map.of("hourly", Arrays.stream(h).boxed().toList(), "forecast", fc));

        } else if (path.equals("/audit")) {
            if (!ses.role().equals("SUPER_ADMIN")) { sendJson(x, 403, Map.of("error", "Admin only")); return; }
            sendJson(x, 200, query("select * from audit_log order by id desc limit 100"));

        } else if (path.equals("/stream")) {                                         // Server-Sent Events
            x.getResponseHeaders().set("Content-Type", "text/event-stream");
            x.getResponseHeaders().set("Cache-Control", "no-cache");
            x.sendResponseHeaders(200, 0);
            OutputStream o = x.getResponseBody();
            o.write(": connected\n\n".getBytes()); o.flush();
            CLIENTS.add(o);

        } else if (path.matches("/units/\\d+/route") && m.equals("POST")) {            // Smart Patrol Route (Nearest-Neighbour)
            long uid = Long.parseLong(path.split("/")[2]);
            var un = query("select * from units where id = ?", uid);
            if (un.isEmpty() || un.get(0).get("lat") == null) { sendJson(x, 404, Map.of("error", "Unit not found")); return; }
            if ("RESPONDING".equals(un.get(0).get("status"))) { sendJson(x, 409, Map.of("error", "Unit is already responding")); return; }
            double sla = num(un.get(0).get("lat")), sln = num(un.get(0).get("lng")), cla = sla, cln = sln, total = 0, separate = 0;
            List<Map<String, Object>> pool = new ArrayList<>(query("select id,type,location,zone,lat,lng from incidents where status = 'Active' and lat is not null order by id desc limit 50"));
            List<Map<String, Object>> stops = new ArrayList<>();
            while (stops.size() < 3 && !pool.isEmpty()) {                             // always go to the closest unvisited incident
                int bi = 0; double bd = 1e9;
                for (int i = 0; i < pool.size(); i++) {
                    double d = km(cla, cln, num(pool.get(i).get("lat")), num(pool.get(i).get("lng")));
                    if (d < bd) { bd = d; bi = i; }
                }
                Map<String, Object> st = pool.remove(bi);
                total += bd;
                separate += 2 * km(sla, sln, num(st.get("lat")), num(st.get("lng")));   // cost if each incident got its own round trip
                cla = num(st.get("lat")); cln = num(st.get("lng"));
                st.put("legKm", round1(bd)); stops.add(st);
            }
            if (stops.isEmpty()) { sendJson(x, 409, Map.of("error", "No active incidents to cover")); return; }
            double routeKm = total + km(cla, cln, sla, sln);
            for (Map<String, Object> st : stops) update("update incidents set status = 'Investigating' where id = ?", st.get("id"));
            Map<String, Object> last = stops.get(stops.size() - 1);
            update("update units set status = 'RESPONDING', zone = ?, lat = ?, lng = ? where id = ?", last.get("zone"), cla, cln, uid);
            audit(ses.user(), "SMART_ROUTE", "unit " + un.get(0).get("code") + " covers " + stops.size() + " incidents, " + round1(routeKm) + " km");
            broadcast(Map.of("event", "dispatch", "unit", un.get(0).get("code"), "zone", last.get("zone")));
            Map<String, Object> res = new LinkedHashMap<>();
            res.put("ok", true); res.put("unit", un.get(0).get("code")); res.put("stops", stops);
            res.put("startLat", sla); res.put("startLng", sln);
            res.put("routeKm", round1(routeKm)); res.put("separateKm", round1(separate));
            res.put("savedPct", separate > 0 ? Math.max(0, Math.round((separate - routeKm) / separate * 100)) : 0);
            sendJson(x, 200, res);

        } else if (path.equals("/logout")) {
            TOKENS.remove(tk); audit(ses.user(), "LOGOUT", "");
            sendJson(x, 200, Map.of("ok", true));

        } else sendJson(x, 404, Map.of("error", "Not found"));
    }
}
