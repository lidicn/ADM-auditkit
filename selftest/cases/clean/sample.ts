// 正确：用 textContent，不解析 HTML
export function renderProfile(user: { name: string }) {
  const el = document.getElementById("app");
  if (el) el.textContent = user.name;
  return user;
}

// 正确：execFile 传数组参数，无 shell 插值
import { execFile } from "child_process";
export function ping(host: string) {
  if (!/^[a-z0-9.-]+$/i.test(host)) throw new Error("bad host");
  execFile("ping", ["-c", "1", host], (err) => { if (err) throw err; });
}

// 正确：凭据走环境变量
const apiKey = process.env.API_KEY;

// 正确：显式类型、参数化查询、crypto 随机
import { randomBytes } from "crypto";
export function makeToken(): string {
  return randomBytes(32).toString("hex");
}

interface Db { query(sql: string, params: unknown[]): Promise<unknown> }

export function findUser(db: Db, name: string) {
  return db.query("SELECT * FROM users WHERE name = $1", [name]);
}
