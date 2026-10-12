// [D-46] .catch 吞错（JS 版）：读失败被静默降级为"空结果"
// 配置/数据拉取失败被当"无数据"（跨项目通则：读失败不能当没有数据）
fetch("/api/config", { signal: AbortSignal.timeout(3000) }).catch(() => null);
