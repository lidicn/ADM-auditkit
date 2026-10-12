use std::process::Command;

// [D-45] spawn 子进程树但只 kill 直接子进程 → 孙进程成孤儿
// Windows 下 cmd.exe → npx.cmd → node(tsx) 进程树，kill 只杀父，孙进程遗留
pub fn launch_sidecar() {
    let mut child = Command::new("cmd")
        .args(["/c", "npx", "tsx", "src/api/main.ts"])
        .spawn()
        .expect("spawn");
    // 退出时只杀父进程
    let _ = child.kill();
}
