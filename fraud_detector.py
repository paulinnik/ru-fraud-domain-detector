# fraud_detector.py — Вычисление признаков фрода для .ru доменов.

import csv
import logging
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# Константы

# Топ российских брендов (транслит + кириллица опционально)
TOP_RU_BRANDS = [
    "yandex",
    "sber",
    "sberbank",
    "vtb",
    "alfabank",
    "alfa",
    "gazprom",
    "rosneft",
    "lukoil",
    "magnit",
    "mvideo",
    "ozon",
    "wildberries",
    "avito",
    "hh",
    "gosuslugi",
    "rosbank",
    "tinkoff",
    "raiffeisen",
    "gazprombank",
    "beeline",
    "megafon",
    "mts",
    "rostelecom",
    "rbc",
    "kommersant",
    "ria",
    "1tv",
    "pochta",
    "russianpost",
    "cdek",
    "detmir",
    "lamoda",
    "citilink",
]

# Ключевые слова, характерные для фрод-доменов
FRAUD_KEYWORDS = [
    "bonus",
    "cashback",
    "promo",
    "акция",
    "скидка",
    "online",
    "cabinet",
    "lk",
    "lichnyj",
    "lichniy",
    "reward",
    "gift",
    "prize",
    "win",
    "lucky",
    "support",
    "help",
    "service",
    "official",
    "secure",
    "safe",
    "verify",
    "confirm",
    "login",
    "signin",
    "account",
    "pay",
    "payment",
]

# Регулярка: [бренд]-[ключевое_слово]-[опц. год].ru
FRAUD_PATTERN = re.compile(
    r"^([a-z0-9]+)-([a-z0-9]+)(?:-([a-z0-9]+))?\.ru$",
    re.IGNORECASE,
)
YEAR_RE = re.compile(r"20\d{2}")

# Регистраторы, часто встречающиеся в фрод-инфраструктуре
CHEAP_REGISTRARS = {
    "namecheap",
    "godaddy",
    "reg.ru",
    "regru",
    "tucows",
    "pdr",
    "publicdomainregistry",
    "hosting concepts",
    "beget",
    "spaceweb",
    "nic.ru",  # массовая регистрация
}

# Пороги
AGE_RED_DAYS = 30  # возраст домена → RED
LEVENSHTEIN_HIGH = 3  # расстояние до бренда → HIGH RISK
REG_DAYS_MEDIUM = 400  # срок регистрации → MEDIUM

# Весовые коэффициенты для итогового score (0–100)
WEIGHTS = {
    "young_domain": 35,
    "brand_similarity": 30,
    "fraud_pattern": 20,
    "cheap_registrar": 8,
    "no_mx": 7,
    "short_registration": 10,
}

# Признаки


def _domain_age_days(reg_date_str: Optional[str]) -> Optional[int]:
    if not reg_date_str or str(reg_date_str) in ("nan", "None", ""):
        return None
    try:
        reg = datetime.strptime(str(reg_date_str)[:10], "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        return (datetime.now(timezone.utc) - reg).days
    except ValueError:
        return None


def feature_young_domain(reg_date_str: Optional[str]) -> dict:
    # Возраст домена < 30 дней → RED
    age = _domain_age_days(reg_date_str)
    flag = age is not None and age < AGE_RED_DAYS
    return {"age_days": age, "young_domain_flag": int(flag)}


def _levenshtein_ratio(a: str, b: str) -> float:
    # Возвращает схожесть [0, 1]: 1 = идентичны.
    return SequenceMatcher(None, a, b).ratio()


def _edit_distance(a: str, b: str) -> int:
    # Классическое расстояние Левенштейна (динамическое программирование).
    n, m = len(a), len(b)
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
    return dp[m]


def feature_brand_similarity(domain: str) -> dict:
    # Минимальное расстояние Левенштейна до топ-брендов
    # Берём только метку домена (без .ru)
    label = domain.lower().replace(".ru", "").split(".")[0]
    # Убираем цифровые суффиксы и разделители
    label_clean = re.sub(r"[-_]", "", label)

    best_brand = ""
    best_dist = 9999
    best_ratio = 0.0

    for brand in TOP_RU_BRANDS:
        dist = _edit_distance(label_clean, brand)
        ratio = _levenshtein_ratio(label_clean, brand)

        # Также проверяем, содержит ли домен бренд как подстроку
        if brand in label_clean and brand != label_clean:
            dist = min(dist, 2)  # подстрока — близко к бренду

        if dist < best_dist:
            best_dist = dist
            best_brand = brand
            best_ratio = ratio

    flag = 0 < best_dist < LEVENSHTEIN_HIGH
    return {
        "closest_brand": best_brand,
        "brand_distance": best_dist,
        "brand_ratio": round(best_ratio, 3),
        "brand_similarity_flag": int(flag),
    }


def feature_fraud_pattern(domain: str) -> dict:
    # Ищет шаблон [бренд]-[ключевое_слово]-[год?].ru
    label = domain.lower()
    match = FRAUD_PATTERN.match(label)
    matched = False
    matched_keyword = ""

    if match:
        parts = [p for p in match.groups() if p]
        # Проверяем, есть ли ключевое слово в любой части
        for part in parts:
            for kw in FRAUD_KEYWORDS:
                if kw in part:
                    matched = True
                    matched_keyword = kw
                    break
            # Или год
            if YEAR_RE.search(part):
                matched = True
                matched_keyword = matched_keyword or "year"

    return {
        "fraud_pattern_flag": int(matched),
        "matched_keyword": matched_keyword,
    }


def feature_cheap_registrar(registrar: Optional[str]) -> dict:
    # Проверяет регистратора на принадлежность к «дешёвым».
    if not registrar or str(registrar) in ("nan", "None", ""):
        return {"cheap_registrar_flag": 0}
    reg_lower = str(registrar).lower()
    flag = any(cheap in reg_lower for cheap in CHEAP_REGISTRARS)
    return {"cheap_registrar_flag": int(flag)}


def feature_no_mx(mx_exists) -> dict:
    # Отсутствие MX-записей → подозрительно.
    try:
        has = int(mx_exists)
    except (TypeError, ValueError):
        has = 0
    return {"no_mx_flag": int(not has)}


def feature_short_registration(registration_days) -> dict:
    # Срок регистрации < 400 дней → MEDIUM.
    try:
        days = int(registration_days)
        flag = days < REG_DAYS_MEDIUM
    except (TypeError, ValueError):
        flag = False
    return {"short_reg_flag": int(flag)}


# Итоговый риск-скор


def compute_risk_score(features: dict) -> tuple[int, str]:
    """
    Возвращает (score 0-100, уровень: LOW / MEDIUM / HIGH / CRITICAL).
    """
    score = 0

    if features.get("young_domain_flag"):
        score += WEIGHTS["young_domain"]

    if features.get("brand_similarity_flag"):
        score += WEIGHTS["brand_similarity"]

    if features.get("fraud_pattern_flag"):
        score += WEIGHTS["fraud_pattern"]

    if features.get("cheap_registrar_flag"):
        score += WEIGHTS["cheap_registrar"]

    if features.get("no_mx_flag"):
        score += WEIGHTS["no_mx"]

    if features.get("short_reg_flag"):
        score += WEIGHTS["short_registration"]

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


# Пайплайн

def analyze_row(row: dict) -> dict:
    # Вычисляет все признаки для одной строки CSV.
    domain = str(row.get("domain", ""))

    f_age = feature_young_domain(row.get("reg_date"))
    f_brand = feature_brand_similarity(domain)
    f_pattern = feature_fraud_pattern(domain)
    f_registrar = feature_cheap_registrar(row.get("registrar"))
    f_mx = feature_no_mx(row.get("mx_exists"))
    f_reg = feature_short_registration(row.get("registration_days"))

    combined = {
        **f_age,
        **f_brand,
        **f_pattern,
        **f_registrar,
        **f_mx,
        **f_reg,
    }
    score, level = compute_risk_score(combined)

    return {
        "domain": domain,
        "age_days": combined["age_days"],
        "closest_brand": combined["closest_brand"],
        "brand_distance": combined["brand_distance"],
        "brand_ratio": combined["brand_ratio"],
        "matched_keyword": combined["matched_keyword"],
        # Флаги
        "young_domain_flag": combined["young_domain_flag"],
        "brand_similarity_flag": combined["brand_similarity_flag"],
        "fraud_pattern_flag": combined["fraud_pattern_flag"],
        "cheap_registrar_flag": combined["cheap_registrar_flag"],
        "no_mx_flag": combined["no_mx_flag"],
        "short_reg_flag": combined["short_reg_flag"],
        # Итог
        "risk_score": score,
        "risk_level": level,
    }


def detect(
    input_csv: str = "raw_domains.csv", output_csv: str = "fraud_results.csv"
) -> pd.DataFrame:

    # Читает raw_domains.csv, вычисляет признаки, сохраняет fraud_results.csv.
    # Возвращает DataFrame с результатами.
    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        logger.error("Файл не найден: %s", input_csv)
        raise

    logger.info("Анализ %d доменов…", len(df))

    results = []
    for _, row in df.iterrows():
        result = analyze_row(row.to_dict())
        results.append(result)
        logger.info(
            "  %-40s score=%-3d  %s",
            result["domain"],
            result["risk_score"],
            result["risk_level"],
        )

    out_df = pd.DataFrame(results)
    out_df.to_csv(output_csv, index=False, encoding="utf-8")
    logger.info("Сохранено: %s", output_csv)
    return out_df


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    detect()
