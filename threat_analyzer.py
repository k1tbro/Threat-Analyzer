#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Итоговое домашнее задание: Анализатор угроз
Инструмент для сбора, анализа данных об угрозах и формирования отчётов.
"""

import json
import os
import requests
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime


# ============== ЭТАП 1: СБОР ДАННЫХ ==============

def load_suricata_logs(log_path: str) -> list:
    """Загрузка логов Suricata из файла eve.json (источник 1)."""
    events = []
    if not os.path.exists(log_path):
        print(f"[!] Файл логов не найден: {log_path}")
        return events

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def load_auth_logs(log_path: str) -> list:
    """Загрузка логов попыток входа (источник 2)."""
    events = []
    if not os.path.exists(log_path):
        return events

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def fetch_cve_api() -> list:
    """
    Получение данных об уязвимостях из CVE API.
    Пробует CIRCL CVE API и NVD API. При недоступности — загружает из data/cve_sample.json.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = os.path.join(base_dir, "data", "cve_sample.json")

    # Попытка 1: CIRCL CVE API
    try:
        response = requests.get("https://cve.circl.lu/api/last/10", timeout=8)
        if response.status_code == 200:
            raw = response.json()
            cve_data = _parse_cve_response(raw)
            if cve_data:
                print("[+] Данные CVE получены из CIRCL API")
                return cve_data
    except Exception as e:
        print(f"[!] CIRCL API: {e}")

    # Попытка 2: локальный файл с демо-данными (имитация второго источника)
    if os.path.exists(sample_path):
        with open(sample_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
        print("[+] Данные CVE загружены из data/cve_sample.json (имитация API)")
        return cve_data

    return get_demo_cve_data()


def _parse_cve_response(raw) -> list:
    """Парсинг ответа CVE API (поддержка разных форматов)."""
    result = []
    items = raw if isinstance(raw, list) else raw.get("vulnerabilities", [raw])

    for item in items:
        doc = item.get("cve", item) if isinstance(item, dict) else item
        if isinstance(doc, dict):
            cve_id = doc.get("id", doc.get("cve_id", ""))
            if not cve_id and "cveMetadata" in doc:
                cve_id = doc["cveMetadata"].get("cveId", "N/A")
            desc = doc.get("summary", doc.get("descriptions", [{}])[0].get("value", "N/A") if doc.get("descriptions") else "N/A")
            cvss = 5.0
            if "metrics" in doc:
                for m in doc.get("metrics", {}).get("cvssMetricV31", []) or doc.get("metrics", {}).get("cvssMetricV30", []):
                    cvss = m.get("cvssData", {}).get("baseScore", cvss)
                    break
            elif "cvss" in doc:
                cvss = doc["cvss"]
            if cve_id:
                result.append({"id": cve_id, "summary": str(desc)[:150], "cvss": float(cvss)})
    return result


def get_demo_cve_data() -> list:
    """Демо-данные CVE при недоступности всех источников."""
    return [
        {"id": "CVE-2024-1234", "summary": "Critical RCE in web server", "cvss": 9.8},
        {"id": "CVE-2024-2345", "summary": "SQL Injection vulnerability", "cvss": 8.5},
        {"id": "CVE-2024-3456", "summary": "XSS in admin panel", "cvss": 6.1},
        {"id": "CVE-2024-4567", "summary": "Path traversal in file upload", "cvss": 7.2},
        {"id": "CVE-2024-5678", "summary": "Authentication bypass", "cvss": 9.1},
    ]


# ============== ЭТАП 2: АНАЛИЗ ДАННЫХ ==============

def analyze_suricata(events: list, auth_events: list = None) -> dict:
    """Анализ логов Suricata и auth: подозрительные IP, частые DNS-запросы."""
    alerts = [e for e in events if e.get("event_type") == "alert"]
    dns_events = [e for e in events if e.get("event_type") == "dns"]

    # Подсчёт IP-адресов источников угроз (Suricata)
    src_ips = [a.get("src_ip") for a in alerts if a.get("src_ip")]
    ip_counts = Counter(src_ips)

    # Обогащение данными из auth-логов (второй источник)
    if auth_events:
        for a in auth_events:
            ip = a.get("ip")
            cnt = a.get("count", 1)
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + cnt

    # Подсчёт частых DNS-запросов (подозрительный трафик)
    dns_domains = []
    for d in dns_events:
        if "dns" in d and "rrname" in d["dns"]:
            dns_domains.append(d["dns"]["rrname"])
    domain_counts = Counter(dns_domains)

    # Высокая критичность алертов
    high_severity = [a for a in alerts if a.get("alert", {}).get("severity", 0) >= 2]

    return {
        "total_alerts": len(alerts),
        "suspicious_ips": dict(ip_counts.most_common(10)),
        "dns_queries": dict(domain_counts),
        "high_severity_alerts": len(high_severity),
        "top_threat_ips": [ip for ip, _ in ip_counts.most_common(5)],
        "frequent_dns": [dom for dom, cnt in domain_counts.items() if cnt >= 2],
    }


def analyze_cve(cve_list: list) -> dict:
    """Анализ CVE: уязвимости с высоким CVSS."""
    results = []
    for cve in cve_list:
        if isinstance(cve, dict):
            cve_id = cve.get("id", cve.get("cve_id", "N/A"))
            summary = cve.get("summary", cve.get("description", "N/A"))
            if isinstance(summary, list):
                summary = summary[0] if summary else "N/A"
            cvss = cve.get("cvss")
            if cvss is None and "cvss" in str(cve).lower():
                cvss = 5.0
            if cvss is None:
                cvss = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 5.0)
            if cvss is None:
                cvss = 5.0
            results.append({"id": cve_id, "summary": str(summary)[:100], "cvss": float(cvss)})

    df = pd.DataFrame(results) if results else pd.DataFrame(columns=["id", "summary", "cvss"])
    high_cvss = [r for r in results if r["cvss"] >= 7.0] if results else []

    return {
        "cve_count": len(results),
        "high_cvss_count": len(high_cvss),
        "top_cve": results[:5] if results else [],
        "cvss_scores": [r["cvss"] for r in results],
    }


# ============== ЭТАП 3: РЕАГИРОВАНИЕ НА УГРОЗЫ ==============

def respond_to_threats(suricata_analysis: dict, cve_analysis: dict) -> list:
    """
    Реагирование на найденные угрозы:
    - вывод сообщения о угрозе;
    - имитация блокировки IP.
    """
    responses = []

    # Реакция на подозрительные IP из логов
    for ip in suricata_analysis.get("top_threat_ips", [])[:3]:
        msg = f"[УГРОЗА] Обнаружен подозрительный IP: {ip}. Имитация блокировки: iptables -A INPUT -s {ip} -j DROP"
        print(msg)
        responses.append({"type": "block_ip", "ip": ip, "action": "simulated_block", "message": msg})

    # Реакция на частые DNS-запросы к подозрительным доменам
    for domain in suricata_analysis.get("frequent_dns", []):
        msg = f"[УГРОЗА] Частые DNS-запросы к подозрительному домену: {domain}. Рекомендуется добавить в blacklist."
        print(msg)
        responses.append({"type": "dns_alert", "domain": domain, "action": "notification", "message": msg})

    # Реакция на уязвимости с высоким CVSS
    for cve in cve_analysis.get("top_cve", []):
        if cve.get("cvss", 0) >= 7.0:
            msg = f"[УГРОЗА] Критическая уязвимость {cve.get('id')} (CVSS: {cve.get('cvss')}). Требуется обновление!"
            print(msg)
            responses.append({"type": "cve_alert", "cve_id": cve["id"], "cvss": cve["cvss"], "action": "notification", "message": msg})

    if not responses:
        print("[OK] Критических угроз не обнаружено.")

    return responses


# ============== ЭТАП 4: ОТЧЁТ И ВИЗУАЛИЗАЦИЯ ==============

def save_report(suricata_analysis: dict, cve_analysis: dict, responses: list, output_path: str):
    """Сохранение отчёта в JSON и CSV."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "sources": ["suricata_logs", "auth_logs", "cve_api"],
        "suricata_analysis": suricata_analysis,
        "cve_analysis": {
            "cve_count": cve_analysis.get("cve_count", 0),
            "high_cvss_count": cve_analysis.get("high_cvss_count", 0),
            "top_cve": cve_analysis.get("top_cve", []),
        },
        "threat_responses": responses,
        "summary": {
            "total_threats_detected": len(responses),
            "suspicious_ips_count": len(suricata_analysis.get("top_threat_ips", [])),
            "critical_vulnerabilities": cve_analysis.get("high_cvss_count", 0),
        },
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[+] Отчёт сохранён: {output_path}")

    # Дополнительно CSV для топ IP и CVE
    csv_path = output_path.replace('.json', '.csv')
    rows = []
    for ip, count in list(suricata_analysis.get("suspicious_ips", {}).items())[:10]:
        rows.append({"type": "suspicious_ip", "value": ip, "count": count})
    for cve in cve_analysis.get("top_cve", [])[:10]:
        rows.append({"type": "cve", "value": cve.get("id"), "cvss": cve.get("cvss")})
    if rows:
        pd.DataFrame(rows).to_csv(csv_path, index=False, encoding='utf-8-sig')
        print(f"[+] CSV отчёт сохранён: {csv_path}")


def create_graph(suricata_analysis: dict, cve_analysis: dict, output_path: str):
    """Построение графика: топ-5 IP по количеству алертов и распределение CVSS."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # График 1: Топ-5 подозрительных IP
    ips = suricata_analysis.get("suspicious_ips", {})
    if ips:
        top_ips = dict(list(ips.items())[:5])
        ax1.barh(list(top_ips.keys()), list(top_ips.values()), color='#e74c3c', alpha=0.8)
        ax1.set_xlabel('Количество алертов')
        ax1.set_ylabel('IP-адрес')
        ax1.set_title('Топ-5 подозрительных IP-адресов')
        ax1.invert_yaxis()
    else:
        ax1.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        ax1.set_title('Топ-5 подозрительных IP')

    # График 2: Распределение CVSS-баллов
    cvss_scores = cve_analysis.get("cvss_scores", [])
    if cvss_scores:
        ax2.hist(cvss_scores, bins=range(0, 11), color='#3498db', alpha=0.8, edgecolor='black')
        ax2.set_xlabel('CVSS балл')
        ax2.set_ylabel('Количество уязвимостей')
        ax2.set_title('Распределение CVSS-баллов уязвимостей')
        ax2.set_xticks(range(0, 11))
    else:
        ax2.text(0.5, 0.5, 'Нет данных', ha='center', va='center')
        ax2.set_title('Распределение CVSS')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] График сохранён: {output_path}")


# ============== ОСНОВНАЯ ФУНКЦИЯ ==============

def main():
    """Главная функция: сбор, анализ, реагирование, отчёт."""
    print("=" * 60)
    print("  АНАЛИЗАТОР УГРОЗ — Итоговое домашнее задание")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    suricata_path = os.path.join(base_dir, "logs", "suricata", "eve.json")
    auth_path = os.path.join(base_dir, "logs", "auth", "auth_attempts.json")
    report_path = os.path.join(base_dir, "report.json")
    graph_path = os.path.join(base_dir, "threat_analysis.png")

    # 1. Сбор данных из двух источников (логи Suricata + логи auth + CVE API)
    print("\n[Этап 1] Сбор данных...")
    suricata_events = load_suricata_logs(suricata_path)
    auth_events = load_auth_logs(auth_path)
    cve_data = fetch_cve_api()

    print(f"  — Загружено событий Suricata: {len(suricata_events)}")
    print(f"  — Загружено записей auth-логов: {len(auth_events)}")
    print(f"  — Получено записей CVE: {len(cve_data)}")

    # 2. Анализ
    print("\n[Этап 2] Анализ данных...")
    suricata_analysis = analyze_suricata(suricata_events, auth_events)
    cve_analysis = analyze_cve(cve_data)

    # 3. Реагирование на угрозы
    print("\n[Этап 3] Реагирование на угрозы...")
    responses = respond_to_threats(suricata_analysis, cve_analysis)

    # 4. Отчёт и график
    print("\n[Этап 4] Формирование отчёта и визуализация...")
    save_report(suricata_analysis, cve_analysis, responses, report_path)
    create_graph(suricata_analysis, cve_analysis, graph_path)

    print("\n" + "=" * 60)
    print("  Анализ завершён успешно!")
    print("=" * 60)


if __name__ == "__main__":
    main()
