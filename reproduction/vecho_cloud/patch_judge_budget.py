"""Make the final judge turn explicit without increasing its ten-turn budget."""
from pathlib import Path
from common import ROOT


def patch(source):
    old = '        response = client.chat.completions.create(model=cfg.model, messages=messages, tools=TOOLS, tool_choice="auto")'
    new = '''        # Reproduction adapter: spend the final available turn on an explicit
        # verdict. Evidence can be insufficient; unknown is a valid outcome.
        final_turn = turn == cfg.max_turns
        if final_turn:
            messages.append({"role": "user", "content": "This is the final permitted turn. Call save_result now using only evidence already gathered. Use unknown when evidence is insufficient; do not infer a true verdict from the budget limit."})
        choice = {"type": "function", "function": {"name": "save_result"}} if final_turn else "auto"
        response = client.chat.completions.create(model=cfg.model, messages=messages, tools=TOOLS, tool_choice=choice)'''
    if new not in source:
        assert source.count(old) == 1, "Unexpected upstream judge implementation"
        source = source.replace(old, new)
    old_break = '''        if not calls:
            messages.append({"role": "assistant", "content": content})
            break'''
    new_break = '''        if not calls:
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": "A verdict must be saved with save_result. Continue within the remaining budget, using unknown if evidence is insufficient."})
            continue'''
    if new_break not in source:
        assert source.count(old_break) == 1
        source = source.replace(old_break, new_break)
    old_identity = '        item = {"fingerprint": fingerprint or record.fingerprint, "vuln_status": status, "analysis": analysis or ""}'
    new_identity = '        item = {"fingerprint": record.fingerprint, "vuln_status": status, "analysis": analysis or ""}'
    if new_identity not in source:
        assert source.count(old_identity) == 1, "Unexpected save_result implementation"
        source = source.replace(old_identity, new_identity)
    return source


if __name__ == "__main__":
    path = ROOT / "judge/vecho_judge/runtime/llm_loop.py"
    original = path.read_text()
    backup = path.with_suffix(".py.before-budget-fix")
    if not backup.exists():
        backup.write_text(original)
    identity_backup = path.with_suffix(".py.before-identity-fix")
    if not identity_backup.exists():
        identity_backup.write_text(original)
    temporary = path.with_suffix(".py.repro-tmp")
    temporary.write_text(patch(original))
    temporary.replace(path)
    print("Judge adapter applied: final-turn save, bound record identity; ten turns and unknown retained")
