import re
from typing import List, Tuple, Optional


class SQLInjectionDetector:
    PATTERNS: List[Tuple[re.Pattern, str, str]] = [
        (re.compile(r"(\bOR\b\s*\d+\s*=\s*\d+)", re.IGNORECASE), "high", "OR boolean injection"),
        (re.compile(r"(\bOR\b\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)", re.IGNORECASE), "high", "OR string injection"),
        (re.compile(r"(\bAND\b\s*\d+\s*=\s*\d+)", re.IGNORECASE), "medium", "AND boolean injection"),
        (re.compile(r"(--|\#|/\*|\*/)", re.IGNORECASE), "high", "SQL comment operator"),
        (re.compile(r"(;.*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION)\b)", re.IGNORECASE), "high", "Stacked query"),
        (re.compile(r"(\bUNION\b\s+ALL?\s+SELECT\b)", re.IGNORECASE), "high", "UNION-based injection"),
        (re.compile(r"(\bSELECT\b\s+\*\s+FROM\b\s+(information_schema|mysql\.user|sys\.users|pg_tables|sqlite_master))", re.IGNORECASE), "critical", "Schema enumeration"),
        (re.compile(r"(\b(SLEEP|BENCHMARK)\s*\()", re.IGNORECASE), "critical", "Time-based blind injection"),
        (re.compile(r"(\bEXEC\b\s*\(|\bEXECUTE\s+immediate\b)", re.IGNORECASE), "high", "Dynamic query execution"),
        (re.compile(r"(\bEVAL\b\s*\()", re.IGNORECASE), "high", "EVAL injection"),
        (re.compile(r"(\bLOAD_FILE\b\s*\(|\bINTO\s+DUMPFILE\b)", re.IGNORECASE), "critical", "File system access"),
        (re.compile(r"(\bxp_cmdshell\b|\bsp_OACreate\b|\bxp_regwrite\b)", re.IGNORECASE), "critical", "OS command execution"),
        (re.compile(r"(\bSELECT\b\s+\*)", re.IGNORECASE), "medium", "SELECT ALL"),
        (re.compile(r"(\bLIKE\b\s*['\"](%|_)[^'\"]*(%|_)[^'\"]*['\"])", re.IGNORECASE), "low", "LIKE wildcard"),
        (re.compile(r"(\bCHAR\s*\([\s\d,]+\))", re.IGNORECASE), "medium", "CHAR() concatenation"),
        (re.compile(r"(\bCONVERT\s*\(|@@\w+)", re.IGNORECASE), "medium", "Type conversion / variable"),
        (re.compile(r"(\bEXISTS\b\s*\()", re.IGNORECASE), "medium", "EXISTS subquery"),
        (re.compile(r"(\bDECLARE\b\s+@\w+)", re.IGNORECASE), "high", "Variable declaration"),
        (re.compile(r"(\bOPENROWSET\b|\bOPENDATASOURCE\b)", re.IGNORECASE), "critical", "Linked server access"),
        (re.compile(r"(\bBULK\b\s+INSERT\b|\bOPENROWSET\b\s*\(.*\bBULK\b)", re.IGNORECASE), "critical", "Bulk insert"),
        (re.compile(r"(\bCASE\b\s+WHEN\b)", re.IGNORECASE), "low", "CASE WHEN conditional"),
        (re.compile(r"(\bSUBSTRING\b\s*\(|\bSUBSTR\b\s*\()", re.IGNORECASE), "low", "SUBSTRING / SUBSTR function"),
        (re.compile(r"(\bASCII\b\s*\(|\bORD\b\s*\()", re.IGNORECASE), "low", "ASCII / ORD function"),
    ]

    RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    @classmethod
    def detect(cls, query: str) -> Tuple[bool, str, str, List[str]]:
        """
        Analyze a query string for SQL injection patterns.

        Returns:
            Tuple of (is_suspicious, highest_severity, explanation, list_of_matched_patterns)
        """
        if not query or not query.strip():
            return False, "low", "No input", []

        matches: List[str] = []
        current_max = "low"
        explanation_parts: List[str] = []

        for pattern, severity, description in cls.PATTERNS:
            if pattern.search(query):
                matches.append(description)
                explanation_parts.append(f"{description} ({severity})")
                if cls.RISK_ORDER.get(severity, 0) > cls.RISK_ORDER.get(current_max, 0):
                    current_max = severity

        is_suspicious = len(matches) > 0
        explanation = ", ".join(explanation_parts) if explanation_parts else "No suspicious patterns"

        return is_suspicious, current_max, explanation, matches

    @classmethod
    def sanitize(cls, value: str) -> str:
        """
        Basic sanitization: escape single quotes and strip comments / line breaks.
        Note: This is not a substitute for parameterized queries.
        """
        if not value:
            return value
        sanitized = value.replace("'", "''")
        sanitized = re.sub(r"--.*?(\r?\n|$)", "", sanitized)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        sanitized = sanitized.replace("\r", " ").replace("\n", " ")
        return sanitized.strip()
