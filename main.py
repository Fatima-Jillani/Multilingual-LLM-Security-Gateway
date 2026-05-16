import time
import re
import yaml
import uuid
import joblib
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

# =========================
# Presidio
# =========================

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern
)

from presidio_anonymizer import AnonymizerEngine

# =========================
# Language Detection
# =========================

from langdetect import detect

# =========================
# APP
# =========================

app = FastAPI(
    title="LLM Security Gateway",
    version="1.0"
)

# =========================
# CONFIG
# =========================

with open("config/gateway_config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

# =========================
# LOAD ML MODEL
# =========================

MODEL_PATH = "models/injection_model.pkl"
VECTORIZER_PATH = "models/vectorizer.pkl"

try:

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

except:

    model = None
    vectorizer = None

# =========================
# REQUEST MODEL
# =========================

class GatewayRequest(BaseModel):

    user_input: str

# =========================
# PRESIDIO SETUP
# =========================

analyzer = AnalyzerEngine()

anonymizer = AnonymizerEngine()

# =========================
# CUSTOM RECOGNIZERS
# =========================

# CNIC

cnic_pattern = Pattern(
    name="cnic_pattern",
    regex=r"\b\d{5}-\d{7}-\d\b",
    score=0.7
)

cnic_recognizer = PatternRecognizer(
    supported_entity="CNIC",
    patterns=[cnic_pattern],
    context=["cnic", "identity", "national id"]
)

analyzer.registry.add_recognizer(cnic_recognizer)

# STUDENT ID

student_pattern = Pattern(
    name="student_pattern",
    regex=r"\b(STD|FAST|NUST)-\d{4,8}\b",
    score=0.65
)

student_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[student_pattern],
    context=["student", "registration"]
)

analyzer.registry.add_recognizer(student_recognizer)

# API KEY

api_pattern = Pattern(
    name="api_pattern",
    regex=r"\b(sk|api)_[A-Za-z0-9]{16,64}\b",
    score=0.9
)

api_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[api_pattern],
    context=["api", "secret", "token"]
)

analyzer.registry.add_recognizer(api_recognizer)

# =========================
# ATTACK PATTERNS
# =========================

ATTACK_PATTERNS = {

    "DIRECT_INJECTION": [
        r"ignore previous instructions",
        r"forget all rules",
        r"override safety",
        r"disregard system prompt"
    ],

    "JAILBREAK": [
        r"developer mode",
        r"jailbreak",
        r"dan mode"
    ],

    "SYSTEM_PROMPT_EXTRACTION": [
        r"show system prompt",
        r"reveal hidden instructions",
        r"print hidden prompt"
    ],

    "SECRET_EXTRACTION": [
        r"api key",
        r"password",
        r"secret token"
    ],

    "RAG_MANIPULATION": [
        r"ignore retrieved context",
        r"modify vector database"
    ]
}

# =========================
# NORMALIZATION
# =========================

def normalize_text(text):

    text = text.lower()

    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "@": "a",
        "$": "s"
    }

    for k, v in replacements.items():

        text = text.replace(k, v)

    text = re.sub(r"\s+", " ", text)

    return text.strip()

# =========================
# LANGUAGE DETECTION
# =========================

def detect_language(text):

    try:

        lang = detect(text)

        languages = {
            "en": "English",
            "ur": "Urdu",
            "ko": "Korean"
        }

        return languages.get(lang, lang)

    except:

        return "unknown"

# =========================
# RULE DETECTOR
# =========================

def detect_rule_based(text):

    score = 0

    reasons = []

    text = normalize_text(text)

    for category, patterns in ATTACK_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, text):

                score += CONFIG["weights"]["rule_pattern_weight"]

                reasons.append(category)

    score = min(score, 100)

    return score, list(set(reasons))

# =========================
# SEMANTIC DETECTOR
# =========================

def detect_semantic(text):

    if model is None or vectorizer is None:

        return 0

    text = normalize_text(text)

    X = vectorizer.transform([text])

    probability = model.predict_proba(X)[0][1]

    return round(probability * 100, 2)

# =========================
# PII RISK
# =========================

def compute_pii_risk(entities):

    if len(entities) == 0:

        return 0

    score = len(entities) * 15

    entity_names = [e.entity_type for e in entities]

    if "API_KEY" in entity_names:

        score += 40

    if "CNIC" in entity_names:

        score += 20

    return min(score, 100)

# =========================
# POLICY ENGINE
# =========================

def policy_engine(
    rule_score,
    semantic_score,
    pii_risk,
    entities
):

    weights = CONFIG["weights"]

    final_risk = (
        (rule_score * weights["rule_weight"])
        +
        (semantic_score * weights["semantic_weight"])
        +
        (pii_risk * weights["pii_weight"])
    )

    final_risk = round(min(final_risk, 100), 2)

    entity_names = [e.entity_type for e in entities]

    # BLOCK

    if rule_score >= CONFIG["thresholds"]["block_rule_threshold"]:

        return "BLOCK", final_risk

    if semantic_score >= CONFIG["thresholds"]["block_semantic_threshold"]:

        return "BLOCK", final_risk

    if "API_KEY" in entity_names:

        return "BLOCK", final_risk

    # MASK

    if pii_risk > 0:

        return "MASK", final_risk

    # ALLOW

    return "ALLOW", final_risk

# =========================
# AUDIT LOGGING
# =========================

LOG_FILE = "results/audit_logs.jsonl"

def write_audit_log(data):

    Path("results").mkdir(exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:

        f.write(str(data) + "\n")

# =========================
# API ENDPOINT
# =========================

@app.post("/gateway")

async def security_gateway(req: GatewayRequest):

    start = time.time()

    user_input = req.user_input

    input_id = str(uuid.uuid4())

    # LANGUAGE

    language = detect_language(user_input)

    # RULE DETECTION

    rule_score, reasons = detect_rule_based(user_input)

    # SEMANTIC DETECTION

    semantic_score = detect_semantic(user_input)

    # PRESIDIO

    analyzer_results = analyzer.analyze(
        text=user_input,
        language="en"
    )

    pii_entities = []

    for item in analyzer_results:

        pii_entities.append({
            "entity": item.entity_type,
            "score": round(item.score, 2)
        })

    # PII RISK

    pii_risk = compute_pii_risk(analyzer_results)

    # POLICY

    decision, final_risk = policy_engine(
        rule_score,
        semantic_score,
        pii_risk,
        analyzer_results
    )

    # SAFE OUTPUT

    if decision == "BLOCK":

        safe_text = "BLOCKED: Security Threat Detected"

    elif decision == "MASK":

        anonymized = anonymizer.anonymize(
            text=user_input,
            analyzer_results=analyzer_results
        )

        safe_text = anonymized.text

    else:

        safe_text = user_input

    # LATENCY

    latency_ms = round(
        (time.time() - start) * 1000,
        2
    )

    # RESPONSE

    response = {

        "input_id": input_id,

        "language": language,

        "rule_score": rule_score,

        "semantic_score": semantic_score,

        "pii_entities": pii_entities,

        "final_risk": final_risk,

        "decision": decision,

        "safe_text": safe_text,

        "reason_codes": reasons,

        "latency_ms": latency_ms
    }

    # LOGGING

    write_audit_log(response)

    return response

# =========================
# HEALTH CHECK
# =========================

@app.get("/health")

async def health():

    return {
        "status": "running"
    }