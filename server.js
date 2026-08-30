// ══════════════════════════════════════════════════════════════
// SERVER.JS
// API que lee las mediciones certificadas desde PostgreSQL (Neon)
// -- energia_relacional (usuarios, roles, viviendas, medidores, estado actual)
// -- energia_series (histórico de lecturas, TimescaleDB)
// y las sirve al dashboard (public/index.html), con login por
// sesión/cookie y permisos según rol (usuario / administrador / supervisor).
// ══════════════════════════════════════════════════════════════

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const PORT = process.env.PORT || 4000;
const SESSION_SECRET = process.env.SESSION_SECRET || "cambia-este-secreto-en-produccion";

const DATABASE_URL_RELACIONAL = process.env.DATABASE_URL_RELACIONAL;
const DATABASE_URL_SERIES = process.env.DATABASE_URL_SERIES;

if (!DATABASE_URL_RELACIONAL || !DATABASE_URL_SERIES) {
  console.error("Faltan DATABASE_URL_RELACIONAL o DATABASE_URL_SERIES en el archivo .env");
  process.exit(1);
}

// ── Conexiones a las dos bases PostgreSQL (Neon) ────────────────
const poolRelacional = new Pool({ connectionString: DATABASE_URL_RELACIONAL, ssl: { rejectUnauthorized: false } });
const poolSeries = new Pool({ connectionString: DATABASE_URL_SERIES, ssl: { rejectUnauthorized: false } });

const app = express();
app.use(cors({ origin: true, credentials: true })); // credentials: true para que las cookies viajen
app.use(express.json());

// ── Sesión por cookie ────────────────────────────────────────────
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // true en Render (usa HTTPS), false en local
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8, // 8 horas
  },
}));

// Sirve el dashboard (public/index.html) como archivos estáticos
app.use(express.static(path.join(__dirname, "public")));

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE DE AUTENTICACIÓN Y ROLES
// ══════════════════════════════════════════════════════════════

// Exige que haya una sesión activa (usuario logueado)
function requireAuth(req, res, next) {
  if (!req.session.usuario) {
    return res.status(401).json({ error: "No has iniciado sesión" });
  }
  next();
}

// Exige que el rol de la sesión esté en la lista permitida
function requireRole(rolesPermitidos) {
  return (req, res, next) => {
    if (!rolesPermitidos.includes(req.session.usuario.rol)) {
      return res.status(403).json({ error: "No tienes permiso para esto" });
    }
    next();
  };
}

// ══════════════════════════════════════════════════════════════
// LOGIN / LOGOUT
// ══════════════════════════════════════════════════════════════

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Faltan username o password" });
    }

    const { rows } = await poolRelacional.query(
      `SELECT u.id, u.username, u.password_hash, r.nombre AS rol, u.vivienda_id
       FROM usuarios u
       JOIN roles r ON u.rol_id = r.id
       WHERE u.username = $1`,
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const usuario = rows[0];
    const coincide = await bcrypt.compare(password, usuario.password_hash);

    if (!coincide) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    // Guardamos solo lo necesario en la sesión (nunca el hash de la contraseña)
    req.session.usuario = {
      id: usuario.id,
      username: usuario.username,
      rol: usuario.rol,
      vivienda_id: usuario.vivienda_id,
    };

    res.json({ ok: true, usuario: req.session.usuario });
  } catch (err) {
    console.error("Error en /api/login:", err);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json(req.session.usuario);
});

// ══════════════════════════════════════════════════════════════
// GESTIÓN DE USUARIOS (solo administrador)
// ══════════════════════════════════════════════════════════════

// Listar todos los usuarios
app.get("/api/usuarios", requireAuth, requireRole(["administrador"]), async (req, res) => {
  try {
    const { rows } = await poolRelacional.query(
      `SELECT u.id, u.username, r.nombre AS rol, v.direccion, m.serial, u.creado_en
       FROM usuarios u
       JOIN roles r ON u.rol_id = r.id
       LEFT JOIN viviendas v ON u.vivienda_id = v.id
       LEFT JOIN medidores m ON m.vivienda_id = v.id
       ORDER BY u.creado_en DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/usuarios:", err);
    res.status(500).json({ error: "Error al consultar los usuarios" });
  }
});

// Registrar un usuario nuevo (solo el admin puede hacerlo — nadie se auto-registra)
app.post("/api/usuarios", requireAuth, requireRole(["administrador"]), async (req, res) => {
  try {
    const { username, password, rol, vivienda_id } = req.body;
    if (!username || !password || !rol) {
      return res.status(400).json({ error: "Faltan username, password o rol" });
    }

    const { rows: rolRows } = await poolRelacional.query(
      "SELECT id FROM roles WHERE nombre = $1",
      [rol]
    );
    if (rolRows.length === 0) {
      return res.status(400).json({ error: "Rol inválido" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { rows } = await poolRelacional.query(
      `INSERT INTO usuarios (username, password_hash, rol_id, vivienda_id, creado_por)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username`,
      [username, passwordHash, rolRows[0].id, vivienda_id || null, req.session.usuario.id]
    );

    res.status(201).json({ ok: true, usuario: rows[0] });
  } catch (err) {
    if (err.code === "23505") { // username duplicado
      return res.status(409).json({ error: "Ese username ya existe" });
    }
    console.error("Error en POST /api/usuarios:", err);
    res.status(500).json({ error: "Error al crear el usuario" });
  }
});

// ══════════════════════════════════════════════════════════════
// MEDICIONES
// Reglas de acceso:
//  - usuario: solo su propia vivienda/medidor
//  - administrador y supervisor: todas las viviendas
// ══════════════════════════════════════════════════════════════

// Resuelve a qué medidor_id(s) tiene acceso la sesión actual.
// Devuelve null si tiene acceso a todos (admin/supervisor).
async function medidoresPermitidos(req) {
  const { rol, vivienda_id } = req.session.usuario;
  if (rol === "administrador" || rol === "supervisor") return null; // sin restricción

  if (!vivienda_id) return []; // no debería pasar, pero por seguridad: sin vivienda = sin datos
  const { rows } = await poolRelacional.query(
    "SELECT id FROM medidores WHERE vivienda_id = $1",
    [vivienda_id]
  );
  return rows.map((r) => r.id);
}

// ── GET /api/measurements/latest?limit=25 ────────────────────────
app.get("/api/measurements/latest", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 25, 500);
    const permitidos = await medidoresPermitidos(req);

    if (permitidos !== null && permitidos.length === 0) {
      return res.json([]);
    }

    const filtroSQL = permitidos !== null ? "WHERE medidor_id = ANY($2)" : "";
    const params = permitidos !== null ? [limit, permitidos] : [limit];

    const { rows } = await poolSeries.query(
      `SELECT * FROM lecturas ${filtroSQL} ORDER BY tiempo DESC LIMIT $1`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/measurements/latest:", err);
    res.status(500).json({ error: "Error al consultar las mediciones" });
  }
});

// ── GET /api/measurements?from=<ISO>&limit=2000 ──────────────────
app.get("/api/measurements", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 2000, 5000);
    const permitidos = await medidoresPermitidos(req);

    if (permitidos !== null && permitidos.length === 0) {
      return res.json([]);
    }

    const condiciones = [];
    const params = [];
    let i = 1;

    if (req.query.from) {
      const desde = new Date(req.query.from);
      if (!isNaN(desde.getTime())) {
        condiciones.push(`tiempo >= $${i++}`);
        params.push(desde);
      }
    }
    if (permitidos !== null) {
      condiciones.push(`medidor_id = ANY($${i++})`);
      params.push(permitidos);
    }

    const whereSQL = condiciones.length ? `WHERE ${condiciones.join(" AND ")}` : "";
    params.push(limit);

    const { rows } = await poolSeries.query(
      `SELECT * FROM lecturas ${whereSQL} ORDER BY tiempo ASC LIMIT $${i}`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/measurements:", err);
    res.status(500).json({ error: "Error al consultar las mediciones" });
  }
});

// ── GET /api/measurements/device/:serial ─────────────────────────
app.get("/api/measurements/device/:serial", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 2000);

    const { rows: medidorRows } = await poolRelacional.query(
      "SELECT id, vivienda_id FROM medidores WHERE serial = $1",
      [req.params.serial]
    );
    if (medidorRows.length === 0) {
      return res.status(404).json({ error: "Medidor no encontrado" });
    }
    const medidor = medidorRows[0];

    const { rol, vivienda_id } = req.session.usuario;
    if (rol === "usuario" && medidor.vivienda_id !== vivienda_id) {
      return res.status(403).json({ error: "No tienes permiso para ver ese medidor" });
    }

    const { rows } = await poolSeries.query(
      "SELECT * FROM lecturas WHERE medidor_id = $1 ORDER BY tiempo DESC LIMIT $2",
      [medidor.id, limit]
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/measurements/device/:serial:", err);
    res.status(500).json({ error: "Error al consultar el medidor" });
  }
});

// ── GET /api/estado (estado actual de tu vivienda, o todas si eres admin/supervisor) ──
app.get("/api/estado", requireAuth, async (req, res) => {
  try {
    const permitidos = await medidoresPermitidos(req);

    if (permitidos !== null && permitidos.length === 0) {
      return res.json([]);
    }

    const filtroSQL = permitidos !== null ? "WHERE e.medidor_id = ANY($1)" : "";
    const params = permitidos !== null ? [permitidos] : [];

    const { rows } = await poolRelacional.query(
      `SELECT e.*, m.serial, v.direccion
       FROM estado_actual e
       JOIN medidores m ON e.medidor_id = m.id
       JOIN viviendas v ON m.vivienda_id = v.id
       ${filtroSQL}`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/estado:", err);
    res.status(500).json({ error: "Error al consultar el estado actual" });
  }
});

// ── GET /api/health ────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ ok: true, db: ["energia_relacional", "energia_series"] });
});

// ── Arranque ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log(`Dashboard disponible en http://localhost:${PORT}/`);
  console.log(`API disponible en http://localhost:${PORT}/api`);
});
// migrador mongo db a neon
