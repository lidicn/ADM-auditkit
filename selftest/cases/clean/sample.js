// 正确：fetch 带超时（JS-06 不报），catch 保留 err 并上报（JS-09 不报）
fetch("/api/config", { signal: AbortSignal.timeout(3000) }).catch((err) => logger.warn("config load failed", err));
