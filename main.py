import argparse
import logging
import sys
import textwrap
from pathlib import Path

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

RAW_CSV = "raw_domains.csv"
RESULT_CSV = "fraud_results.csv"


# Демонстрационный режим (без сетевых запросов)
_DEMO_ROWS = [
    # domain,                reg_date,    registrar,               ip,              mx_exists, registration_days
    ("yandex.ru",            "2000-01-01", "RU-CENTER-RU",          "5.255.255.77",  1,         3650),
    ("sberbank.ru",          "1997-05-15", "RU-CENTER-RU",          "185.60.190.10", 1,         9490),
    ("vtb.ru",               "1999-09-01", "RU-CENTER-RU",          "194.165.60.1",  1,         8760),
    ("gosuslugi.ru",         "2009-08-17", "RIPE",                  "81.19.88.68",   1,         5475),
    ("rbc.ru",               "1998-11-01", "RU-CENTER-RU",          "87.240.190.67", 1,         9125),
    # Фрод-паттерны
    ("sber-bonus-2024.ru",   "2024-10-01", "Namecheap, Inc.",        "185.220.101.5", 0,         365),
    ("vtb-cashback-online.ru","2024-11-15","GoDaddy.com, LLC",       "104.21.15.200", 0,         365),
    ("yandex-promo2024.ru",  "2024-09-20", "Namecheap, Inc.",        "172.67.68.100", 0,         365),
    ("alfa-bank-bonus.ru",   "2024-12-01", "PDR Ltd.",               "192.168.1.1",   0,         365),
    ("sberfank.ru",          "2024-11-28", "GoDaddy.com, LLC",       "45.33.32.156",  0,         365),
]


def _write_demo_raw_csv(path: str) -> None:
    """Записывает синтетические тестовые данные в raw_domains.csv."""
    import csv
    fieldnames = ["domain", "reg_date", "registrar", "ip", "mx_exists", "registration_days"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in _DEMO_ROWS:
            writer.writerow(dict(zip(fieldnames, row)))
    logger.info("Тестовый CSV записан: %s", path)


# Отчёт в консоль
def _safe_print(text: str) -> None:
    """Печатает строку с обработкой кодировки Windows-терминала."""
    import sys
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))


def print_report(df: pd.DataFrame) -> None:
    """Красивый вывод итогов в терминал."""
    sep = "-" * 110
    _safe_print("\n" + sep)
    _safe_print(f"{'ДОМЕН':<42} {'ВОЗРАСТ':>8} {'БРЕНД':<14} {'DIST':>5} {'КЛЮЧСЛОВО':<14} {'SCORE':>6} {'УРОВЕНЬ':<10}")
    _safe_print(sep)

    sorted_df = df.sort_values("risk_score", ascending=False)

    for _, r in sorted_df.iterrows():
        age_val = r["age_days"]
        age_str = f"{int(age_val)} d." if pd.notna(age_val) else "n/a"
        kw = str(r["matched_keyword"]) if r.get("matched_keyword") else "-"
        _safe_print(
            f"{r['domain']:<42} {age_str:>8} {str(r['closest_brand']):<14} {int(r['brand_distance']):>5} "
            f"{kw:<14} {int(r['risk_score']):>6} {r['risk_level']:<10}"
        )

    _safe_print(sep)

    # Статистика
    counts = df["risk_level"].value_counts()
    _safe_print("\nSTATISTICS:")
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = counts.get(lvl, 0)
        bar = "#" * n
        _safe_print(f"  {lvl:<10} {n:>4}  {bar}")

    high_risk = df[df["risk_level"].isin(["CRITICAL", "HIGH"])]
    if not high_risk.empty:
        _safe_print(f"\n[!] HIGH/CRITICAL domains: {len(high_risk)}")
        for _, r in high_risk.iterrows():
            flags = []
            if r.get("young_domain_flag"):
                flags.append("young")
            if r.get("brand_similarity_flag"):
                flags.append(f"similar to '{r['closest_brand']}'")
            if r.get("fraud_pattern_flag"):
                flags.append(f"pattern '{r['matched_keyword']}'")
            if r.get("cheap_registrar_flag"):
                flags.append("cheap registrar")
            if r.get("no_mx_flag"):
                flags.append("no MX")
            if r.get("short_reg_flag"):
                flags.append("short registration")
            _safe_print(f"   {r['domain']}: {', '.join(flags)}")
    _safe_print("")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Детектирование фрод-доменов .ru",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Примеры:
          python main.py --test               # тестовый набор, без сети
          python main.py --days 7 --limit 50  # сбор из crt.sh
          python main.py --input raw.csv      # только анализ готового CSV
        """),
    )
    p.add_argument("--test", action="store_true", help="Использовать встроенный тестовый набор")
    p.add_argument("--days", type=int, default=7, help="Глубина выборки из crt.sh (дней)")
    p.add_argument("--limit", type=int, default=100, help="Максимум доменов из crt.sh")
    p.add_argument("--input", type=str, default=None, help="Готовый CSV вместо сбора")
    p.add_argument("--enrich", type=str, default=None,
                   help="CSV со списком доменов (остальные поля пустые) — запустить WHOIS+DNS и анализ")
    p.add_argument("--raw-out", type=str, default=RAW_CSV, help="Путь для raw CSV")
    p.add_argument("--out", type=str, default=RESULT_CSV, help="Путь для итогового CSV")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Шаг 1: Получить raw_domains.csv 
    if args.enrich:
        # Читаем только колонку domain, запускаем полное обогащение
        import pandas as pd
        from data_collector import collect, enrich_domain, _save_csv
        from concurrent.futures import ThreadPoolExecutor, as_completed

        src = pd.read_csv(args.enrich)
        domains = src["domain"].dropna().str.strip().tolist()
        logger.info("=== ШАГ 1: Обогащение %d доменов из %s ===", len(domains), args.enrich)

        rows = [None] * len(domains)
        completed = 0
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(enrich_domain, d): i for i, d in enumerate(domains)}
            for future in as_completed(futures):
                idx = futures[future]
                completed += 1
                try:
                    rows[idx] = future.result()
                    logger.info("[%d/%d] %s", completed, len(domains), domains[idx])
                except Exception as exc:
                    logger.warning("%s — ошибка: %s", domains[idx], exc)
                    rows[idx] = {"domain": domains[idx], "reg_date": None,
                                 "registrar": None, "ip": None,
                                 "mx_exists": 0, "registration_days": None}

        rows = [r for r in rows if r]
        _save_csv(rows, args.raw_out)
        raw_path = args.raw_out

    elif args.input:
        raw_path = args.input
        logger.info("Используем готовый CSV: %s", raw_path)
    elif args.test:
        raw_path = args.raw_out
        _write_demo_raw_csv(raw_path)
    else:
        from data_collector import collect
        logger.info("=== ШАГ 1: Сбор доменов из crt.sh ===")
        collect(days=args.days, limit=args.limit, output=args.raw_out)
        raw_path = args.raw_out

    if not Path(raw_path).exists():
        logger.error("Файл не найден: %s", raw_path)
        sys.exit(1)

    # Шаг 2: Детекция фрода 
    from fraud_detector import detect
    logger.info("=== ШАГ 2: Анализ признаков фрода ===")
    result_df = detect(input_csv=raw_path, output_csv=args.out)

    # Шаг 3: Отчёт 
    logger.info("=== ШАГ 3: Итоговый отчёт ===")
    print_report(result_df)
    logger.info("Итоговый CSV: %s", args.out)


if __name__ == "__main__":
    main()
