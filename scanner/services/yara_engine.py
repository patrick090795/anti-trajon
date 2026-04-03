import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


def get_rules_path():
    current_file = Path(__file__).resolve()
    scanner_dir = current_file.parent.parent
    return scanner_dir / "rules" / "trojan_rules.yar"


@lru_cache(maxsize=4)
def _compile_rules(rules_path, modified_time_ns):
    yara = import_yara()
    return yara.compile(filepath=rules_path)


def import_yara():
    import yara

    return yara


def get_compiled_rules():
    rules_path = get_rules_path()
    modified_time_ns = rules_path.stat().st_mtime_ns
    return _compile_rules(str(rules_path), modified_time_ns)


def get_yara_scan_report(filepath):
    try:
        rules = get_compiled_rules()
        matches = rules.match(filepath=filepath)
        return {
            "matches": [match.rule for match in matches],
            "available": True,
        }
    except Exception:
        logger.exception("YARA scanning failed for %s", filepath)
        return {
            "matches": [],
            "available": False,
        }


def scan_with_yara(filepath):
    return get_yara_scan_report(filepath)["matches"]
