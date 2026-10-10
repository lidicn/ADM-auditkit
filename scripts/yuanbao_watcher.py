#!/usr/bin/env python3
"""
元宝审计保姆脚本（精简版）
核心任务：盯住元宝，卡住了自动发"继续"，直到元宝说"全部完成"。
报告不需要脚本存——元宝对话历史和腾讯文档里都有，最后手动导出即可。
"""
import argparse
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, Page

# ============ 配置 ============
CHECK_INTERVAL = 5       # 每 5 秒检查一次
STALL_TIMEOUT = 90       # 空闲超过 90 秒 = 卡住了
MAX_CONTINUE = 5         # 最多自动发 5 次"继续"，超过叫人
NO_CHANGE_TIMEOUT = 300   # 生成中但 5 分钟内容没变化 = 卡住了（元宝跑命令需要时间）

CDP_URL = "http://localhost:9222"


def log(msg: str, level: str = "INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def get_chat_text(page: Page) -> str:
    try:
        return page.evaluate("() => document.body.innerText")
    except Exception:
        return ""


def is_generating(page: Page) -> bool:
    try:
        btn = page.query_selector(".SendButton_sendButton__g3Lcb")
        if btn:
            cls = btn.get_attribute("class") or ""
            return "sendStop" in cls
    except Exception:
        pass
    return False


def send_message(page: Page, text: str):
    try:
        editor = page.query_selector(".ql-editor")
        if editor:
            editor.click()
            editor.fill(text)
            time.sleep(0.5)
            send_btn = page.query_selector(".SendButton_sendButton__g3Lcb")
            if send_btn:
                send_btn.click()
                log(f"已发送: {text}")
    except Exception as e:
        log(f"发送失败: {e}", "ERROR")


def find_latest_round(text: str) -> int:
    matches = re.findall(r"ROUND_(\d+)_DONE", text)
    if matches:
        return max(int(m) for m in matches)
    return 0


def watch(page: Page, project: str):
    log("=" * 60)
    log(f"项目: {project} | 纯保姆模式（不抓报告）")
    log(f"停滞判定: 空闲 {STALL_TIMEOUT}s / 生成中无变化 {NO_CHANGE_TIMEOUT}s")
    log(f"最大自动继续: {MAX_CONTINUE} 次")
    log("=" * 60)

    baseline_text = get_chat_text(page)
    current_round = find_latest_round(baseline_text)
    baseline_has_all_done = "ALL_DONE" in baseline_text

    log(f"当前进度: 已完成第 {current_round} 轮")
    if baseline_has_all_done:
        log("注意：基线里已有 ALL_DONE 字样，只在新增内容里检测", "WARN")

    idle_time = 0
    no_change_time = 0
    last_text_len = len(baseline_text)
    continue_count = 0
    saved_len = len(baseline_text)

    while True:
        try:
            generating = is_generating(page)
            current_text = get_chat_text(page)
            text_len = len(current_text)
            new_text = current_text[saved_len:] if text_len > saved_len else ""

            # ---- 心跳：每 30 秒打印一次 ----
            if int(time.time()) % 30 < CHECK_INTERVAL:
                status = "生成中" if generating else "空闲"
                log(f"[心跳] {status} | 已完成 {current_round} 轮 | 对话 {text_len} 字")

            # ---- 检测内容变化 ----
            if text_len != last_text_len:
                no_change_time = 0
                last_text_len = text_len
            else:
                no_change_time += CHECK_INTERVAL

            # ---- 生成中但卡住了（内容长时间不变）----
            if generating and no_change_time >= NO_CHANGE_TIMEOUT:
                log(f"生成中但 {no_change_time}s 无变化，发「继续」", "WARN")
                send_message(page, "继续")
                no_change_time = 0
                time.sleep(5)

            # ---- 检测新轮次 ----
            latest = find_latest_round(current_text)
            if latest > current_round:
                log(f"=== 第 {latest} 轮完成 ===")
                saved_len = text_len
                current_round = latest
                continue_count = 0
                no_change_time = 0

            # ---- 检测 ALL_DONE ----
            if baseline_has_all_done:
                all_done_now = "ALL_DONE" in new_text
            else:
                all_done_now = "ALL_DONE" in current_text

            if all_done_now:
                log("=== 检测到 ALL_DONE，全部完成！===", "EVENT")
                log(f"共完成 {current_round} 轮审计。报告请去腾讯文档导出。")
                return

            # ---- 空闲太久 = 卡住 ----
            if not generating:
                idle_time += CHECK_INTERVAL
                if idle_time >= STALL_TIMEOUT:
                    if continue_count < MAX_CONTINUE:
                        continue_count += 1
                        log(f"空闲 {idle_time}s，发「继续」（第 {continue_count} 次）", "WARN")
                        send_message(page, "继续")
                        idle_time = 0
                        time.sleep(5)
                    else:
                        log(f"连续卡住 {MAX_CONTINUE} 次！需要人工介入", "FATAL")
                        log("手动检查元宝后按回车继续...", "FATAL")
                        input()
                        idle_time = 0
                        continue_count = 0
            else:
                idle_time = 0

            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            log(f"循环异常: {e}，10 秒后重试", "ERROR")
            time.sleep(10)


def main():
    global STALL_TIMEOUT, MAX_CONTINUE
    parser = argparse.ArgumentParser(description="元宝审计保姆脚本")
    parser.add_argument("--project", choices=["AF", "DB", "MA"], default="AF")
    parser.add_argument("--stall-timeout", type=int, default=STALL_TIMEOUT)
    parser.add_argument("--max-continue", type=int, default=MAX_CONTINUE)
    args = parser.parse_args()

    STALL_TIMEOUT = args.stall_timeout
    MAX_CONTINUE = args.max_continue

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_URL)
        page = None
        for ctx in browser.contexts:
            for pg in ctx.pages:
                if "yuanbao.tencent.com/chat" in pg.url:
                    page = pg
                    break
            if page:
                break

        if not page:
            log("没找到元宝聊天页面！", "ERROR")
            sys.exit(1)

        log(f"页面: {page.title()}")
        watch(page, args.project)


if __name__ == "__main__":
    main()
