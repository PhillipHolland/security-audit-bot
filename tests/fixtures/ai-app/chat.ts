// Fictional fixture for rule tests.
import OpenAI from "openai";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";

const client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(cors({ origin: "https://app.example.test", credentials: true }));
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);
const anon = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

app.get("/me", (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  const claims = jwt.decode(req.headers.authorization);
  res.json(claims);
});
