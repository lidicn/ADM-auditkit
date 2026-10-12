use std::process::Command;

// 正确（POSIX）：用 libc::kill 至少给直接子发信号（缓解被 exclude）
pub fn launch_sidecar_safe() {
    let child = Command::new("npx").spawn().expect("spawn");
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM); }
}

// 正确：spawn 后 wait 回收，不 kill 任何进程（无孤儿风险）
pub fn run_and_wait() {
    let mut child = Command::new("npx").spawn().expect("spawn");
    let _ = child.wait();
}
