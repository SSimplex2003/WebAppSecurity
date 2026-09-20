import "dotenv/config";
import express from "express";
import helmet from "helmet";

const app = express();
const port = process.env.PORT ?? 3000;

app.use(helmet());
app.use(express.json({ limit: "100kb" }));

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// Auth, session and vault routes land in Checkpoint 2 (see docs/checkpoint-1-design.md).

app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
