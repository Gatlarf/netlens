"""Guard: the AI has to know about everything Netlens can report. A new kind of event must be either a problem the incident engine and the
investigation understand, or be listed here as information only, so adding one forces the decision (see the note on keeping the AI in step)."""

import glob
import re

from app import ask, incidents

INFORMATION_ONLY = {
    "central_reachable", "device_deleted", "device_log", "device_new", "device_online", "guest_backup_recovered", "inventory_available", "ip_changed", "ip_reused", "licence_expiring",
    "link_up", "llm_model_unavailable", "login_failed", "metric_ok", "net_ok", "os_changed", "plugin_update_skipped", "plugin_updated", "service_up", "vpn_up", "wake_sent", "wifi_roamed",
    "firmware_update", "remediation_pending", "remediation_ran", "remediation_recovered",
}


def emitted_kinds() -> set[str]:
    kinds: set[str] = set()
    for path in glob.glob("app/**/*.py", recursive=True):
        kinds |= set(re.findall(r'add_event\(\s*\w+,\s*f?"([a-z_]+)"', open(path, encoding="utf-8").read()))
    return kinds


def test_every_kind_of_event_is_a_known_problem_or_information_only():
    known = incidents.PROBLEMS | set(incidents.RECOVERS) | set(incidents.RECOVERS.values()) | INFORMATION_ONLY
    unknown = sorted(emitted_kinds() - known)
    assert not unknown, f"teach app/incidents.py (PROBLEMS, WORDS) about {unknown}, or list them as information only in this test"


def test_new_problem_kinds_have_words_for_the_report():
    assert {"vuln_critical", "dns_failed", "host_timeout", "port_unexpected"} <= set(incidents.WORDS)


def test_every_new_question_can_be_chosen_by_its_words():
    from app import ask_extra

    routed = {t for t, _ in ask_extra.RULES}
    assert {"vulnerabilities", "traffic", "notifications", "oncall", "investigate", "system_log"} <= routed
    assert routed <= set(ask.TOOLS)
