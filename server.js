// ══════════════════════════════════════════════════════════════
// SERVER.JS
// API que lee las mediciones certificadas desde MongoDB Atlas
// (las mismas que guarda puente_iot_blockchain2.py) y las sirve
// al dashboard (public/index.html).
// ══════════════════════════════════════════════════════════════

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const { MongoClient } = require("mongodb");

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "certificacion_energetica";
const COLLECTION_NAME = process.env.COLLECTION_NAME || "measurements";

if (!MONGO_URI) {
  console.error("Falta MONGO_URI en el archivo .env");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Sirve el dashboard (public/index.html) como archivos estáticos
app.use(express.static(path.join(__dirname, "public")));

let coleccion;

// ── Normaliza un documento de Mongo para el frontend ──────────
// Los campos ya vienen con los nombres correctos desde
// guardar_en_mongo() en el puente Python, así que esto
// principalmente limpia el _id y asegura el formato de timestamp.
function normalizeDoc(doc) {
  return {
    id: doc._id?.toString(),
    deviceId: doc.deviceId,
    timestamp: doc.timestamp instanceof Date ? doc.timestamp.toISOString() : doc.timestamp,
    voltage: doc.voltage,
    current: doc.current,
    power: doc.power,
    energy: doc.energy,
    frequency: doc.frequency,
    powerFactor: doc.powerFactor,
    temperature: doc.temperature,
    txHash: doc.txHash,
    blockNumber: doc.blockNumber,
    verified: !!doc.verified,
  };
}

// ── GET /api/measurements/latest?limit=25 ──────────────────────
// Últimas N mediciones, orden descendente por fecha (más reciente primero).
app.get("/api/measurements/latest", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 25, 500);

    const docs = await coleccion
      .find({})
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();

    res.json(docs.map(normalizeDoc));
  } catch (err) {
    console.error("Error en /api/measurements/latest:", err);
    res.status(500).json({ error: "Error al consultar las mediciones" });
  }
});

// ── GET /api/measurements?from=<ISO>&limit=2000 ─────────────────
// Mediciones desde una fecha, orden ascendente (para la gráfica histórica).
app.get("/api/measurements", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 2000, 5000);
    const filtro = {};

    if (req.query.from) {
      const desde = new Date(req.query.from);
      if (!isNaN(desde.getTime())) {
        filtro.timestamp = { $gte: desde };
      }
    }

    const docs = await coleccion
      .find(filtro)
      .sort({ timestamp: 1 })
      .limit(limit)
      .toArray();

    res.json(docs.map(normalizeDoc));
  } catch (err) {
    console.error("Error en /api/measurements:", err);
    res.status(500).json({ error: "Error al consultar las mediciones" });
  }
});

// ── GET /api/measurements/:deviceId ─────────────────────────────
// Historial de un medidor específico.
app.get("/api/measurements/device/:deviceId", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 2000);

    const docs = await coleccion
      .find({ deviceId: req.params.deviceId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();

    res.json(docs.map(normalizeDoc));
  } catch (err) {
    console.error("Error en /api/measurements/device/:deviceId:", err);
    res.status(500).json({ error: "Error al consultar el medidor" });
  }
});

// ── GET /api/health ──────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ ok: true, db: DB_NAME, collection: COLLECTION_NAME });
});

// ── Arranque: conecta a Mongo y luego levanta el servidor ───────
async function iniciar() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  coleccion = client.db(DB_NAME).collection(COLLECTION_NAME);
  console.log(`Conectado a MongoDB -> ${DB_NAME}.${COLLECTION_NAME}`);

  app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Dashboard disponible en http://localhost:${PORT}/`);
    console.log(`API disponible en http://localhost:${PORT}/api`);
  });
}

iniciar().catch((err) => {
  console.error("No se pudo iniciar el servidor:", err);
  process.exit(1);
});
