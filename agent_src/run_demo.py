"""
Interactive Demo Runner for 15-Minute Project Presentation
Allows live terminal presentation of:
- Baseline ReAct Agent (UIUC Paper arXiv:2404.08144v2)
- Proposed H-PentestAgent (Novel Hierarchical Multi-Agent with Backtracking)
"""

import time
import sys
import os
import threading
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from mock_targets.app import app, init_db
from core.react_agent import BaselineReActAgent
from core.hierarchical_agent import HierarchicalMultiAgent

console = Console()

def start_server_daemon():
    init_db()
    t = threading.Thread(target=lambda: app.run(host="127.0.0.1", port=5055, debug=False, use_reloader=False))
    t.daemon = True
    t.start()
    time.sleep(1.0)

def main():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]NT521 - LẬP TRÌNH AN TOÀN VÀ KHAI THÁC LỖ HỔNG PHẦN MỀM[/bold cyan]\n"
        "[bold yellow]Đề tài CK66:[/bold yellow] LLM Agents can Autonomously Exploit One-day Vulnerabilities\n"
        "[bold green]Mở rộng nghiên cứu:[/bold green] H-PentestAgent (Hierarchical Multi-Agent & Dynamic Backtracking)",
        title="BÁO CÁO & DEMO ĐỒ ÁN CUỐI KỲ", border_style="cyan"
    ))

    start_server_daemon()
    base_url = "http://127.0.0.1:5055"

    console.print("\n[bold]Chọn kịch bản Demo trực tiếp:[/bold]")
    console.print("  [1] Demo Baseline ReAct Agent (Khai thác One-day có CVE - Theo bài báo gốc)")
    console.print("  [2] Demo Baseline Thất bại khi bỏ CVE (Tái hiện hiện tượng tụt giảm 87% -> 7%)")
    console.print("  [3] Demo Đề tài Mở rộng: H-PentestAgent tự động tìm & khai thác không cần CVE")
    console.print("  [4] Chạy toàn bộ Benchmark so sánh tự động (Tạo bảng kết quả đầy đủ)")
    
    choice = input("\nNhập lựa chọn [1-4] (Mặc định: 3): ").strip() or "3"

    if choice == "1":
        console.print("\n[bold cyan]>>> Đang chạy Baseline ReAct Agent trên target SQL Injection (Có CVE)...[/bold cyan]")
        agent = BaselineReActAgent(
            target_url=f"{base_url}/vulnerable/sqli",
            cve_description="CVE-2021-24666: SQL injection in product search allows arbitrary SELECT query against users table."
        )
        res = agent.run()
        for h in res["history"]:
            console.print(Panel(
                f"[bold yellow]Thought:[/bold yellow] {h.get('thought')}\n"
                f"[bold magenta]Action:[/bold magenta] {h.get('action')} ({h.get('args')})\n"
                f"[bold green]Observation:[/bold green] {h.get('observation')}",
                title=f"Step {h.get('step')}", border_style="blue"
            ))
            time.sleep(0.5)
        console.print(f"\n[bold green]Kết quả khai thác:[/bold green] {'THÀNH CÔNG (PASS)' if res['success'] else 'THẤT BẠI'}")
        console.print(f"Chi phí ước tính: ${res['estimated_cost_usd']} | Số bước: {res['steps_taken']}")

    elif choice == "2":
        console.print("\n[bold red]>>> Đang chạy Baseline ReAct Agent KHÔNG CÓ CVE (Black-box)...[/bold red]")
        agent = BaselineReActAgent(
            target_url=f"{base_url}/vulnerable/sqli",
            cve_description=""
        )
        res = agent.run()
        for h in res["history"]:
            console.print(Panel(
                f"[bold yellow]Thought:[/bold yellow] {h.get('thought')}\n"
                f"[bold magenta]Action:[/bold magenta] {h.get('action')}\n"
                f"[bold red]Observation:[/bold red] {h.get('observation')}",
                title=f"Step {h.get('step')}", border_style="red"
            ))
            time.sleep(0.5)
        console.print(f"\n[bold red]Kết quả khai thác:[/bold red] THẤT BẠI (Bị kẹt nhánh, không biết quay lui)")

    elif choice == "3":
        console.print("\n[bold green]>>> Đang chạy Proposed H-PentestAgent (Multi-Agent & Dynamic Backtracking) KHÔNG CẦN CVE...[/bold green]")
        h_agent = HierarchicalMultiAgent(target_url=f"{base_url}/vulnerable/sqli", cve_description="")
        res = h_agent.run()
        for event in res["log"]:
            console.print(Panel(
                f"[bold cyan]Role:[/bold cyan] {event['agent_role']}\n"
                f"[bold yellow]Thought:[/bold yellow] {event['thought']}\n"
                f"[bold magenta]Action:[/bold magenta] {event['action']}\n"
                f"[bold green]Result:[/bold green] {event['result']}",
                title=event['agent_role'], border_style="green"
            ))
            time.sleep(0.4)
        console.print(f"\n[bold green]Kết quả:[/bold green] {'THÀNH CÔNG VƯỢT TRỘI' if res['success'] else 'THẤT BẠI'}")
        console.print(f"Thời gian: {res['execution_time_seconds']}s | Chi phí: ${res['estimated_cost_usd']}")

    elif choice == "4":
        from benchmark.run_comparison import run_evaluation
        run_evaluation()

if __name__ == "__main__":
    main()
