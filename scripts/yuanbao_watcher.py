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
        # 先滚动到页面底部，确保输入框可见
        page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(0.3)

        editor = page.query_selector(".ql-editor")
        if editor:
            # 用 JS 直接设置内容，不依赖点击
            page.evaluate("""([el, text]) => {
                el.innerHTML = '';
                el.innerText = text;
            }""", [editor, text])
            time.sleep(0.3)

            # 按回车发送
            page.keyboard.press("Enter")
            log(f"已发送: {text}")
    except Exception as e:
        log(f"发送失败: {e}", "ERROR")


def find_latest_round(text: str) -> int:
    matches = re.findall(r"ROUND_(\d+)_DONE", text)
    if matches:
        return max(int(m) for m in matches)
    return 0


def watch(page: Page, project: str, start_round: int = 0):
    log("=" * 60)
    log(f"项目: {project} | 纯保姆模式（不抓报告）")
    log(f"停滞判定: 空闲 {STALL_TIMEOUT}s / 生成中无变化 {NO_CHANGE_TIMEOUT}s")
    log(f"最大自动继续: {MAX_CONTINUE} 次")
    log("=" * 60)

    baseline_text = get_chat_text(page)
    saved_len = len(baseline_text)

    log(f"基线已记录（{saved_len} 字符），等待新轮次出现...")

    baseline_has_all_done = "ALL_DONE" in baseline_text
    if baseline_has_all_done:
        log("注意：基线里已有 ALL_DONE 字样，只在新增内容里检测", "WARN")

    idle_time = 0
    no_change_time = 0
    last_text_len = saved_len
    continue_count = 0
    new_round_count = 0  # 从启动后检测到的新轮次数

    while True:
        try:
            generating = is_generating(page)
            current_text = get_chat_text(page)
            text_len = len(current_text)
            new_text = current_text[saved_len:] if text_len > saved_len else ""

            # ---- 心跳：每 30 秒打印一次 ----
            if int(time.time()) % 30 < CHECK_INTERVAL:
                status = "生成中" if generating else "空闲"
                log(f"[心跳] {status} | 新轮次 {new_round_count} | 对话 {text_len} 字")

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

            # ---- 检测新轮次（只在新增内容里找）----
            if "ROUND_" in new_text and "_DONE" in new_text:
                round_match = re.search(r"ROUND_(\d+)_DONE", new_text)
                if round_match:
                    round_num = int(round_match.group(1))
                    new_round_count += 1
                    log(f"=== 检测到新轮次标记：ROUND_{round_num}_DONE（累计 {new_round_count} 轮）===")
                    saved_len = text_len
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
    parser.add_argument("--start-round", type=int, default=0,
                        help="起始轮次（0=自动从页面读取；换项目时手动指定）")
    parser.add_argument("--stall-timeout", type=int, default=STALL_TIMEOUT)
    parser.add_argument("--max-continue", type=int, default=MAX_CONTINUE)
    parser.add_argument("--url", type=str, default="", help="指定元宝对话 URL（默认自动找最新的）")
    args = parser.parse_args()

    STALL_TIMEOUT = args.stall_timeout
    MAX_CONTINUE = args.max_continue

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_URL)

        # 列出所有元宝对话页面
        yuanbao_pages = []
        for ctx in browser.contexts:
            for pg in ctx.pages:
                if "yuanbao.tencent.com/chat" in pg.url:
                    yuanbao_pages.append(pg)

        print(f"[诊断] 找到 {len(yuanbao_pages)} 个元宝对话页面:")
        for i, pg in enumerate(yuanbao_pages):
            title = pg.title()
            print(f"  [{i}] {title[:40]}...")
            print(f"      URL: {pg.url[:80]}...")

        # 选页面：指定 URL 优先，否则选最后一个（最新打开的）
        page = None
        if args.url:
            for pg in yuanbao_pages:
                if args.url in pg.url:
                    page = pg
                    break
            if not page:
                print(f"[错误] 没找到包含 '{args.url}' 的页面", "ERROR")
                sys.exit(1)
        elif yuanbao_pages:
            page = yuanbao_pages[-1]  # 最后一个 = 最新打开的
            print(f"[诊断] 使用最新打开的页面: {page.title()[:40]}...")
        else:
            log("没找到元宝聊天页面！", "ERROR")
            sys.exit(1)
            log("没找到元宝聊天页面！", "ERROR")
            sys.exit(1)

        log(f"页面: {page.title()}")
        watch(page, args.project, start_round=args.start_round)


if __name__ == "__main__":
    main()
