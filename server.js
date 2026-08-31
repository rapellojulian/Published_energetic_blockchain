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

// Zona horaria de referencia para "día actual" y "mes actual".
// Sin esto, Postgres calcula esos límites en UTC, y en Colombia (UTC-5)
// eso hace que "el día" cambie a las 7:00 p.m. hora local en vez de a medianoche.
const ZONA_HORARIA_LOCAL = "America/Bogota";

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
app.set("trust proxy", 1); // necesario en Render: confía en el proxy para saber que la conexión es HTTPS
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

// Listar todos los usuarios (administrador y supervisor pueden ver; solo administrador puede crear)
app.get("/api/usuarios", requireAuth, requireRole(["administrador", "supervisor"]), async (req, res) => {
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

// Eliminar un usuario (solo el admin puede hacerlo)
app.delete("/api/usuarios/:id", requireAuth, requireRole(["administrador"]), async (req, res) => {
  try {
    const { id } = req.params;

    if (Number(id) === req.session.usuario.id) {
      return res.status(400).json({ error: "No puedes eliminar tu propio usuario mientras tienes la sesión activa" });
    }

    const { rows } = await poolRelacional.query(
      "DELETE FROM usuarios WHERE id = $1 RETURNING username",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Ese usuario no existe" });
    }

    res.json({ ok: true, eliminado: rows[0].username });
  } catch (err) {
    if (err.code === "23503") {
      // Este usuario aparece como "creado_por" de algún otro usuario — no se puede
      // borrar sin romper esa referencia. En la práctica no debería pasar con tus
      // 3 usuarios de prueba, pero por seguridad avisamos en vez de fallar en seco.
      return res.status(409).json({ error: "No se puede eliminar: este usuario registró a otros usuarios" });
    }
    console.error("Error en DELETE /api/usuarios/:id:", err);
    res.status(500).json({ error: "Error al eliminar el usuario" });
  }
});

// ══════════════════════════════════════════════════════════════
// VIVIENDAS (solo administrador) — usadas por el panel "Crear usuario"
// del dashboard, para no depender de SQL manual en Neon.
// ══════════════════════════════════════════════════════════════

// Listar viviendas (con su medidor, si tiene) para el desplegable "vivienda existente"
app.get("/api/viviendas", requireAuth, requireRole(["administrador"]), async (req, res) => {
  try {
    const { rows } = await poolRelacional.query(
      `SELECT v.id, v.direccion, m.serial
       FROM viviendas v
       LEFT JOIN medidores m ON m.vivienda_id = v.id
       ORDER BY v.id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("Error en /api/viviendas:", err);
    res.status(500).json({ error: "Error al consultar las viviendas" });
  }
});

// Crear una vivienda nueva junto con su medidor, en una sola transacción
// (equivalente a los dos INSERT que antes hacíamos a mano por SQL).
app.post("/api/viviendas", requireAuth, requireRole(["administrador"]), async (req, res) => {
  const { direccion, serial } = req.body;
  if (!direccion || !serial) {
    return res.status(400).json({ error: "Faltan direccion o serial" });
  }

  const cliente = await poolRelacional.connect();
  try {
    await cliente.query("BEGIN");

    const { rows: viviendaRows } = await cliente.query(
      "INSERT INTO viviendas (direccion) VALUES ($1) RETURNING id",
      [direccion]
    );
    const viviendaId = viviendaRows[0].id;

    await cliente.query(
      "INSERT INTO medidores (vivienda_id, serial) VALUES ($1, $2)",
      [viviendaId, serial]
    );

    await cliente.query("COMMIT");
    res.status(201).json({ ok: true, vivienda_id: viviendaId, serial });
  } catch (err) {
    await cliente.query("ROLLBACK");
    if (err.code === "23505") { // serial duplicado
      return res.status(409).json({ error: "Ese serial de medidor ya existe" });
    }
    console.error("Error en POST /api/viviendas:", err);
    res.status(500).json({ error: "Error al crear la vivienda/medidor" });
  } finally {
    cliente.release();
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

// Trae un mapa { medidor_id: serial } desde energia_relacional (bases distintas, no se puede hacer JOIN directo)
async function mapaSeriales() {
  const { rows } = await poolRelacional.query("SELECT id, serial FROM medidores");
  const mapa = {};
  rows.forEach((m) => { mapa[m.id] = m.serial; });
  return mapa;
}

// Convierte una fila de 'lecturas' + el mapa de seriales al formato que espera el dashboard
function normalizeLectura(r, mapa) {
  return {
    id: `${r.medidor_id}-${new Date(r.tiempo).getTime()}`,
    deviceId: mapa[r.medidor_id] || String(r.medidor_id),
    timestamp: r.tiempo instanceof Date ? r.tiempo.toISOString() : r.tiempo,
    voltage: r.voltaje,
    current: r.corriente,
    power: r.potencia,
    energy: r.energia_kwh,
    temperature: r.temperatura,
    txHash: r.tx_hash,
    blockNumber: r.block_number,
    verified: !!r.tx_hash,
  };
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

    const [{ rows }, mapa] = await Promise.all([
      poolSeries.query(`SELECT * FROM lecturas ${filtroSQL} ORDER BY tiempo DESC LIMIT $1`, params),
      mapaSeriales(),
    ]);
    res.json(rows.map((r) => normalizeLectura(r, mapa)));
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

    const [{ rows }, mapa] = await Promise.all([
      poolSeries.query(`SELECT * FROM lecturas ${whereSQL} ORDER BY tiempo ASC LIMIT $${i}`, params),
      mapaSeriales(),
    ]);
    res.json(rows.map((r) => normalizeLectura(r, mapa)));
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

    const [{ rows }, { rows: diarios }, { rows: mensuales }] = await Promise.all([
      poolRelacional.query(
        `SELECT e.*, m.serial, v.direccion
         FROM estado_actual e
         JOIN medidores m ON e.medidor_id = m.id
         JOIN viviendas v ON m.vivienda_id = v.id
         ${filtroSQL}`,
        params
      ),
      // Energía acumulada del día: el ESP32 manda un total acumulado (no un delta),
      // así que el consumo de hoy = (acumulado más reciente de hoy) - (acumulado más antiguo de hoy).
      // Usamos AT TIME ZONE dos veces para que "el día" empiece a medianoche en hora
      // de Colombia, no a medianoche UTC (que en Colombia cae a las 7:00 p.m.).
      poolSeries.query(
        `SELECT medidor_id, COALESCE(MAX(energia_kwh) - MIN(energia_kwh), 0) AS energia_acumulada
         FROM lecturas
         WHERE tiempo >= (date_trunc('day', now() AT TIME ZONE '${ZONA_HORARIA_LOCAL}') AT TIME ZONE '${ZONA_HORARIA_LOCAL}')
         GROUP BY medidor_id`
      ),
      // Mismo cálculo, pero desde el día 1 del mes actual (también en hora de Colombia).
      poolSeries.query(
        `SELECT medidor_id, COALESCE(MAX(energia_kwh) - MIN(energia_kwh), 0) AS consumo_mensual
         FROM lecturas
         WHERE tiempo >= (date_trunc('month', now() AT TIME ZONE '${ZONA_HORARIA_LOCAL}') AT TIME ZONE '${ZONA_HORARIA_LOCAL}')
         GROUP BY medidor_id`
      ),
    ]);

    const mapaDiario = {};
    diarios.forEach((d) => { mapaDiario[d.medidor_id] = Number(d.energia_acumulada); });

    const mapaMensual = {};
    mensuales.forEach((m) => { mapaMensual[m.medidor_id] = Number(m.consumo_mensual); });

    const conCalculos = rows.map((r) => ({
      ...r,
      energia_acumulada: mapaDiario[r.medidor_id] ?? 0,
      consumo_mensual: mapaMensual[r.medidor_id] ?? 0,
    }));

    res.json(conCalculos);
  } catch (err) {
    console.error("Error en /api/estado:", err);
    res.status(500).json({ error: "Error al consultar el estado actual" });
  }
});

// ── GET /api/health ────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ ok: true, db: ["energia_relacional", "energia_series"] });
});

// ── GET /api/historico-mensual ───────────────────────────────────
// Consumo de cada mes por separado (no solo el actual), calculado
// igual que consumo_mensual: resta entre el acumulado más reciente
// y el más antiguo dentro de cada mes. Nada se pierde porque 'lecturas'
// nunca borra datos viejos. Los meses se agrupan en hora de Colombia
// (mismo motivo que en /api/estado: evitar el desfase de UTC).
app.get("/api/historico-mensual", requireAuth, async (req, res) => {
  try {
    const permitidos = await medidoresPermitidos(req);
    if (permitidos !== null && permitidos.length === 0) {
      return res.json([]);
    }

    const filtroSQL = permitidos !== null ? "WHERE medidor_id = ANY($1)" : "";
    const params = permitidos !== null ? [permitidos] : [];

    const { rows } = await poolSeries.query(
      `SELECT medidor_id,
              date_trunc('month', tiempo AT TIME ZONE '${ZONA_HORARIA_LOCAL}') AS mes,
              MAX(energia_kwh) - MIN(energia_kwh) AS consumo
       FROM lecturas
       ${filtroSQL}
       GROUP BY medidor_id, date_trunc('month', tiempo AT TIME ZONE '${ZONA_HORARIA_LOCAL}')
       ORDER BY medidor_id, mes DESC`,
      params
    );

    const mapa = await mapaSeriales();
    res.json(rows.map((r) => ({
      deviceId: mapa[r.medidor_id] || String(r.medidor_id),
      mes: r.mes,
      consumo: Number(r.consumo),
    })));
  } catch (err) {
    console.error("Error en /api/historico-mensual:", err);
    res.status(500).json({ error: "Error al consultar el histórico mensual" });
  }
});

// ── Arranque ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log(`Dashboard disponible en http://localhost:${PORT}/`);
  console.log(`API disponible en http://localhost:${PORT}/api`);
});
