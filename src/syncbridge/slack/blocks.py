"""Block Kit rendering for synced records. The hash of the rendered message is stored in the
mapping, so an update that would not change what people see in Slack is skipped."""

from __future__ import annotations

import hashlib
import json

STATUS_EMOJI = {
    "New": ":new:",
    "Working": ":hammer_and_wrench:",
    "Escalated": ":rotating_light:",
    "On Hold": ":double_vertical_bar:",
    "Closed": ":white_check_mark:",
}
PRIORITY_EMOJI = {
    "High": ":red_circle:",
    "Medium": ":large_orange_circle:",
    "Low": ":large_green_circle:",
}


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_case(case: dict, record_url: str) -> tuple[str, list[dict]]:
    number = case.get("CaseNumber", "")
    subject = _esc(case.get("Subject") or "(no subject)")
    status = case.get("Status", "")
    priority = case.get("Priority", "")
    text = f"Case {number}: {case.get('Subject') or ''} [{status}, {priority}]"
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"Case {number}", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*<{record_url}|{subject}>*"}},
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Status*\n{STATUS_EMOJI.get(status, '')} {_esc(status)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Priority*\n{PRIORITY_EMOJI.get(priority, '')} {_esc(priority)}",
                },
                {"type": "mrkdwn", "text": f"*Account*\n{_esc(case.get('AccountName') or '—')}"},
                {"type": "mrkdwn", "text": f"*Owner*\n{_esc(case.get('OwnerName') or '—')}"},
            ],
        },
    ]
    if case.get("Description"):
        desc = _esc(case["Description"])
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": desc[:600] + ("…" if len(desc) > 600 else "")},
            }
        )
    actions = []
    if status != "Closed":
        if status != "Escalated":
            actions.append(_button("Escalate", "case_escalate", case["Id"], "danger"))
        actions.append(_button("Close case", "case_close", case["Id"], "primary"))
    else:
        actions.append(_button("Reopen", "case_reopen", case["Id"]))
    blocks.append(
        {"type": "actions", "block_id": f"case_actions:{case['Id']}", "elements": actions}
    )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Synced from Salesforce · reply in thread to add a case message",
                }
            ],
        }
    )
    return text, blocks


def render_case_message(msg: dict) -> tuple[str, list[dict]]:
    author = _esc(msg.get("Author__c") or "Salesforce")
    body = _esc(msg.get("Body__c") or "")
    text = f"{msg.get('Author__c') or 'Salesforce'}: {msg.get('Body__c') or ''}"
    return text, [
        {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900] or " "}},
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"{author} · from Salesforce"}],
        },
    ]


def _button(label: str, action_id: str, value: str, style: str | None = None) -> dict:
    b = {
        "type": "button",
        "text": {"type": "plain_text", "text": label},
        "action_id": action_id,
        "value": value,
    }
    if style:
        b["style"] = style
    if action_id == "case_close":
        b["confirm"] = {
            "title": {"type": "plain_text", "text": "Close this case?"},
            "text": {"type": "mrkdwn", "text": "The case is closed in Salesforce."},
            "confirm": {"type": "plain_text", "text": "Close case"},
            "deny": {"type": "plain_text", "text": "Cancel"},
        }
    return b


def content_hash(text: str, blocks: list[dict]) -> str:
    raw = json.dumps({"t": text, "b": blocks}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
