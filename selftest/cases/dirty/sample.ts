// [D-35] XSS：直接写 innerHTML
export function renderProfile(user: any) {
  document.getElementById("app").innerHTML = "<h1>" + user.name + "</h1>";
  return user;
}

// [D-36] 命令注入：模板串拼进 exec
import { exec } from "child_process";
export function ping(host: string) {
  exec(`ping -c 1 ${host}`, (err) => console.log(err));
}

// [D-37] 硬编码凭据
const API_KEY = "sk_live_TEST_FAKE_KEY_REPLACE_ME";

// [D-38] 关闭 TLS 校验
export const agent = { rejectUnauthorized: false };

// [D-39] CORS 通配
export const corsOrigin = "*";

// [D-40] SQL 拼接
export function findUser(db: any, name: string) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

// [D-41] 用非密码学随机生成 token
export function makeToken() {
  return Math.random().toString(36) + "-session";
}
