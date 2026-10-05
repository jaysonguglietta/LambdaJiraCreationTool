from __future__ import annotations

from collections.abc import Iterable


def text(value: object, *, bold: bool = False, code: bool = False, href: str | None = None) -> dict:
    node: dict[str, object] = {"type": "text", "text": str(value)}
    marks: list[dict[str, object]] = []
    if bold:
        marks.append({"type": "strong"})
    if code:
        marks.append({"type": "code"})
    if href:
        marks.append({"type": "link", "attrs": {"href": href}})
    if marks:
        node["marks"] = marks
    return node


def paragraph(*content: dict | str) -> dict:
    nodes = [item if isinstance(item, dict) else text(item) for item in content]
    return {"type": "paragraph", "content": nodes}


def heading(level: int, value: str) -> dict:
    return {"type": "heading", "attrs": {"level": level}, "content": [text(value)]}


def bullet_list(items: Iterable[str]) -> dict:
    return {
        "type": "bulletList",
        "content": [{"type": "listItem", "content": [paragraph(item)]} for item in items],
    }


def ordered_list(items: Iterable[str]) -> dict:
    return {
        "type": "orderedList",
        "attrs": {"order": 1},
        "content": [{"type": "listItem", "content": [paragraph(item)]} for item in items],
    }


def code_block(value: str) -> dict:
    return {"type": "codeBlock", "content": [text(value)]}


def table(rows: Iterable[tuple[str, str]]) -> dict:
    content = []
    for label, value in rows:
        content.append(
            {
                "type": "tableRow",
                "content": [
                    {
                        "type": "tableHeader",
                        "attrs": {},
                        "content": [paragraph(text(label, bold=True))],
                    },
                    {
                        "type": "tableCell",
                        "attrs": {},
                        "content": [paragraph(value)],
                    },
                ],
            }
        )
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": content,
    }


def document(nodes: Iterable[dict]) -> dict:
    return {"version": 1, "type": "doc", "content": list(nodes)}


def plain_text(node: object) -> str:
    """Flatten an ADF document for tests and audit logging."""
    if isinstance(node, dict):
        own = node.get("text", "")
        children = " ".join(plain_text(child) for child in node.get("content", []))
        return f"{own} {children}".strip()
    if isinstance(node, list):
        return " ".join(plain_text(item) for item in node)
    return ""
