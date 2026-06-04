# data_collector.py — Сбор и обогащение .ru доменов из crt.sh + WHOIS + DNS.

import csv
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import dns.resolver
import requests
import whois

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

OUTPUT_CSV = "raw_domains.csv"
FIELDNAMES = ["domain", "reg_date", "registrar", "ip", "mx_exists", "registration_days"]

# Целевые бренд-запросы к источникам CT-логов
# Запрашиваем домены, похожие на известные бренды — это релевантнее
# для фрод-детектора, чем слепая выборка всех .ru
_BRAND_QUERIES = [
    "sber", "vtb", "alfa", "gazprom", "tinkoff", "yandex",
    "ozon", "wildberries", "avito", "gosuslugi", "pochta",
    "beeline", "megafon", "mts", "rosneft", "lukoil",
    "raiffeisen", "rosbank", "citilink", "mvideo", "detmir",
]

_CRTSH_URL = "https://crt.sh/"
_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


def _normalize_domain(name: str) -> Optional[str]:
    # Нормализует имя домена; возвращает None если не .ru второго уровня
    name = name.lstrip("*").lstrip(".").lower().strip()
    if not name.endswith(".ru"):
        return None
    if name.count(".") != 1:  # только второй уровень
        return None
    return name


def _crtsh_brand_query(brand: str, days: int) -> list[str]:
    # Запрашивает crt.sh по одному бренд-паттерну.
    # Возвращает домены, где бренд встречается в имени.
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    domains: list[str] = []

    for pattern in (f"%{brand}%.ru", f"{brand}%.ru"):
        try:
            resp = requests.get(
                _CRTSH_URL,
                params={"q": pattern, "output": "json"},
                timeout=15,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception as exc:
            logger.debug("crt.sh %s: %s", pattern, exc)
            continue

        for entry in data:
            # Фильтр по дате выдачи сертификата
            nb = entry.get("not_before", "") or ""
            if nb:
                try:
                    ts = datetime.strptime(nb[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        continue
                except ValueError:
                    pass

            for raw in (entry.get("common_name", ""), entry.get("name_value", "")):
                for part in str(raw).splitlines():
                    normalized = _normalize_domain(part)
                    if normalized:
                        domains.append(normalized)
        break  # Достаточно одного паттерна

    return domains


def _certspotter_brand_query(brand: str, days: int) -> list[str]:
 
    # Запрашивает certspotter.com (бесплатный CT API, не требует ключа).
    # Возвращает домены, содержащие бренд.

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    domains: list[str] = []
    try:
        resp = requests.get(
            _CERTSPOTTER_URL,
            params={
                "domain": f"{brand}.ru",
                "include_subdomains": "true",
                "expand": "dns_names",
                "after": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            headers={"User-Agent": "fraud-domain-detector/1.0"},
            timeout=15,
        )
        if resp.status_code == 200:
            for cert in resp.json():
                for name in cert.get("dns_names", []):
                    normalized = _normalize_domain(name)
                    if normalized:
                        domains.append(normalized)
    except Exception as exc:
        logger.debug("certspotter %s: %s", brand, exc)
    return domains


def _crtsh_is_alive() -> bool:
    # Быстрая проверка доступности crt.sh — один запрос, 10 секунд
    try:
        resp = requests.get(
            _CRTSH_URL,
            params={"q": "sber.ru", "output": "json"},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception:
        return False


def fetch_crtsh_domains(days: int = 7, limit: int = 500) -> list[str]:
    # Возвращает уникальные .ru домены за последние `days` дней.
    # Стратегия: быстрая проверка crt.sh → если недоступен, сразу certspotter.
    
    logger.info(
        "Поиск доменов по %d брендам (последние %d дней, лимит %d)…",
        len(_BRAND_QUERIES), days, limit,
    )

    # Один быстрый ping — решаем, какой источник использовать
    logger.info("Проверка доступности crt.sh…")
    use_crtsh = _crtsh_is_alive()
    if use_crtsh:
        logger.info("crt.sh доступен — используем его")
    else:
        logger.info("crt.sh недоступен — переключаемся на certspotter")

    seen: set[str] = set()
    domains: list[str] = []

    for brand in _BRAND_QUERIES:
        if len(domains) >= limit:
            break

        if use_crtsh:
            new = _crtsh_brand_query(brand, days)
            if not new:
                # crt.sh перестал отвечать в процессе — переключаемся
                logger.warning("crt.sh перестал отвечать, переключение на certspotter")
                use_crtsh = False
                new = _certspotter_brand_query(brand, days)
        else:
            new = _certspotter_brand_query(brand, days)

        for d in new:
            if d not in seen:
                seen.add(d)
                domains.append(d)
                if len(domains) >= limit:
                    break

        time.sleep(0.4)

    source = "crt.sh" if use_crtsh else "certspotter"
    logger.info("Источник: %s | получено %d доменов", source, len(domains))
    return domains


# WHOIS
def get_whois_info(domain: str) -> dict:
    """Возвращает reg_date, registrar, registration_days (или None при ошибке)."""
    result = {"reg_date": None, "registrar": None, "registration_days": None}
    try:
        w = whois.whois(domain)

        # reg_date — может быть list или datetime
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if not creation.tzinfo:
                creation = creation.replace(tzinfo=timezone.utc)
            result["reg_date"] = creation.strftime("%Y-%m-%d")
            result["registration_days"] = (datetime.now(timezone.utc) - creation).days

        # expiry — вычисляем срок регистрации в днях
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry and creation:
            if not expiry.tzinfo:
                expiry = expiry.replace(tzinfo=timezone.utc)
            result["registration_days"] = (expiry - creation).days

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        result["registrar"] = str(registrar).strip() if registrar else None

    except Exception as exc:
        logger.debug("WHOIS %s: %s", domain, exc)

    return result


# Passive DNS (HackerTarget)
def get_ip(domain: str) -> Optional[str]:
    """Получает текущий IP через HackerTarget hostsearch API."""
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=10,
        )
        if resp.status_code == 200 and "," in resp.text:
            # Формат: domain,ip
            first_line = resp.text.strip().splitlines()[0]
            parts = first_line.split(",")
            if len(parts) >= 2:
                return parts[1].strip()
    except Exception as exc:
        logger.debug("IP lookup %s: %s", domain, exc)

    # Fallback: обычный DNS A-запрос
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        return str(answers[0])
    except Exception:
        pass

    return None


# MX lookup
def has_mx(domain: str) -> bool:
    """Проверяет наличие MX-записей."""
    try:
        dns.resolver.resolve(domain, "MX", lifetime=5)
        return True
    except Exception:
        return False


# Сборка пайплайна

def enrich_domain(domain: str) -> dict:
    """Обогащает один домен всеми метаданными."""
    logger.info("  Обогащение: %s", domain)

    whois_info = get_whois_info(domain)
    ip = get_ip(domain)
    mx = has_mx(domain)

    return {
        "domain": domain,
        "reg_date": whois_info["reg_date"],
        "registrar": whois_info["registrar"],
        "ip": ip,
        "mx_exists": int(mx),
        "registration_days": whois_info["registration_days"],
    }


def collect(days: int = 7, limit: int = 100, output: str = OUTPUT_CSV,
            workers: int = 8) -> list[dict]:
    # Главная функция модуля.
    # Возвращает список словарей и сохраняет CSV. workers — количество параллельных потоков для обогащения.

    from concurrent.futures import ThreadPoolExecutor, as_completed

    domains = fetch_crtsh_domains(days=days, limit=limit)

    if not domains:
        logger.warning("Домены не получены — используем тестовый набор")
        domains = _test_domains()

    total = len(domains)
    logger.info("Начинаем обогащение %d доменов (потоков: %d)…", total, workers)

    rows: list[dict] = [None] * total
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {pool.submit(enrich_domain, d): i for i, d in enumerate(domains)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            completed += 1
            try:
                rows[idx] = future.result()
                logger.info("[%d/%d] %s", completed, total, domains[idx])
            except Exception as exc:
                logger.warning("[%d/%d] %s — ошибка: %s", completed, total, domains[idx], exc)
                rows[idx] = {"domain": domains[idx], "reg_date": None,
                             "registrar": None, "ip": None,
                             "mx_exists": 0, "registration_days": None}

    rows = [r for r in rows if r is not None]
    _save_csv(rows, output)
    logger.info("Сохранено: %s (%d строк)", output, len(rows))
    return rows


def _save_csv(rows: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def _test_domains() -> list[str]:
    # Тестовый набор — используется при недоступности crt.sh.
    return [
        # Легитимные
        "yandex.ru",
        "sberbank.ru",
        "vtb.ru",
        "gosuslugi.ru",
        "rbc.ru",
        # Синтетические фрод-паттерны для демонстрации
        "sber-bonus-2024.ru",
        "vtb-cashback-online.ru",
        "yandex-promo2024.ru",
        "alfa-bank-bonus.ru",
        "sberfank.ru",
    ]


if __name__ == "__main__":
    collect(days=7, limit=50)
