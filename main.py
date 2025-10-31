import gradio as gr
import requests, json, urllib3, re, datetime

# ------------------------------
#  CONFIGURATION
# ------------------------------
FW_HOST   = ""
FW_TOKEN  = ""
LMAAS_URL = ""
LMAAS_KEY = ""
MODEL     = "Mistral-Small-24B-W8A8"

# Relative logo paths
CERTIN_LOGO = "certin.png"
REDHAT_LOGO = "redhat.svg"

urllib3.disable_warnings()
SYSTEM_PROMPT = "You are a network NOC assistant. Reply in 5–8 short bullet points, plain English, no code blocks."

# ------------------------------
#  HELPERS
# ------------------------------
def clean_json_text(s):
    if not s:
        return ""
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        if s.endswith("```"):
            s = s[:-3]
    s = s.strip()
    first, last = s.find("{"), s.rfind("}")
    if first != -1 and last != -1 and last > first:
        s = s[first:last + 1]
    return s.strip()

def pretty_or_raw_json(s):
    cleaned = clean_json_text(s)
    try:
        obj = json.loads(cleaned)
        return json.dumps(obj, indent=2)
    except Exception:
        return cleaned

def _post_stream(url, headers, payload, timeout=60):
    r = requests.post(url, headers=headers, json=payload, timeout=timeout, stream=True)
    r.raise_for_status()
    for line in r.iter_lines():
        if not line:
            continue
        s = line.decode("utf-8")
        if not s.startswith("data: "):
            continue
        data = s[6:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
            delta = chunk.get("choices", [{}])[0].get("delta", {})
            piece = delta.get("content")
            if piece:
                yield piece
        except json.JSONDecodeError:
            continue

def firewall_data():
    url = f"{FW_HOST}/api/v2/monitor/vpn/ipsec/select"
    headers = {"Authorization": f"Bearer {FW_TOKEN}"}
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

# ------------------------------
#  STREAMING + APPROVAL
# ------------------------------
def analyzeFW():
    data = firewall_data()
    if not data:
        msg = "Failed to retrieve firewall data."
        yield (msg, "", "", msg, "")
        return

    headers = {"Authorization": f"Bearer {LMAAS_KEY}", "Content-Type": "application/json"}
    payload_summary = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Summarize these IPSec tunnel states for a manager:\n\n{json.dumps(data)}"},
        ],
        "temperature": 0.2,
        "stream": True,
    }

    summary_header = "## Tunnel Health Analysis\n"
    summary_accum = ""
    yield (summary_header, "", "", summary_header, "")

    try:
        for piece in _post_stream(LMAAS_URL, headers, payload_summary, timeout=60):
            summary_accum += piece
            yield (summary_header + summary_accum, "", "", summary_header + summary_accum, "")
    except Exception as e:
        err = f"{summary_header}Error while summarizing: {e}"
        yield (err, "", "", err, "")
        return

    # Proposed actions
    down = []
    for res in data.get("results", []):
        for proxy in res.get("proxyid", []):
            if proxy.get("status") == "down":
                name = res.get("name") or res.get("p2name") or "unknown"
                down.append(name)
    down = sorted(set(down))

    actions_header = "\n\n## Proposed Actions\n"
    base_summary = summary_header + summary_accum + actions_header
    yield (base_summary, "", "", base_summary, "")

    if not down:
        final = base_summary + "\nNo down tunnels. No actions proposed."
        yield (final, "", "", final, "")
        return

    action_prompt = """
Return ONLY strict JSON with this schema:
{
 "actions":[{"method":"POST","url":"","payload":{},"why":"","risk":"low|medium|high"}]
}
Rules:
- Only suggest safe, non-disruptive actions like notifications.
- Prefer a single POST to a notify endpoint containing an array of tunnel names.
- Do NOT suggest config changes, reboots, or resets.
- If unsure, return {"actions":[]}.
"""
    payload_actions = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": action_prompt},
            {"role": "user", "content": f"Tunnels down: {', '.join(down)}\nRaw JSON for reference: {json.dumps(data)}"},
        ],
        "temperature": 0.1,
        "stream": True,
    }

    actions_accum = ""
    for piece in _post_stream(LMAAS_URL, headers, payload_actions, timeout=60):
        actions_accum += piece
        yield (base_summary, pretty_or_raw_json(actions_accum), "", base_summary, actions_accum)

    final_state = base_summary + "\n\n---\n\nPlease review the proposed actions and provide approval below."
    yield (final_state, pretty_or_raw_json(actions_accum), "", final_state, actions_accum)

def handleApproval(answer, summary_state, actions_state):
    answer = (answer or "").strip().lower()
    base = summary_state or ""
    approved_text = ""

    if answer in ("y", "yes"):
        updated = base + "\n\n## Approval received\n**Performing action...**"
        raw = clean_json_text(actions_state or "")
        try:
            obj = json.loads(raw)
            obj["approved"] = True
            obj["approved_at"] = datetime.datetime.now().isoformat(timespec="seconds")
            approved_text = json.dumps(obj, indent=2)
        except Exception:
            approved_text = pretty_or_raw_json(actions_state or "")
    elif answer in ("n", "no"):
        updated = base + "\n\n---\n\n### Approval denied. No action taken."
    else:
        updated = base + "\n\n---\n\n### Invalid input. No action taken."

    return updated, gr.update(), approved_text, updated, actions_state

# ------------------------------
#  UI
# ------------------------------
def main():
    css = """
    body { background:#f7f7fb; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color:#111; }
    .gradio-container { max-width: 980px; margin: 40px auto; background:#fff; border-radius:16px; box-shadow:0 6px 20px rgba(0,0,0,.06); padding:28px 28px 36px; }
    #app-header { display:flex; align-items:center; gap:16px; border-bottom:1px solid #eee; padding-bottom:12px; margin-bottom:20px; }
    #app-header .logos { display:flex; align-items:center; gap:12px; }
    #app-header img { height:34px; width:auto; object-fit:contain; display:block; }
    #app-title { flex:1; text-align:center; font-weight:700; font-size:20px; color:#1f3a5f; }
    #summary-box { color:#111 !important; background:#fff; border:1px solid #eee; border-radius:12px; padding:14px 16px; line-height:1.55; max-height:460px; overflow:auto; }
    .gr-code { border-radius:12px !important; border:1px solid #e5e7eb !important; }
    .gr-code>pre, .gr-code code, #summary-box pre, #summary-box code {
      background:#ffffff !important; color:#111111 !important; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace !important;
      font-size:13px !important; line-height:1.55 !important; white-space: pre-wrap !important; word-break: break-word !important;
    }
    textarea, input[type="text"] { background:#fff !important; color:#111 !important; border-radius:10px !important; border:1px solid #e5e7eb !important; }
    button { background:#1f3a5f !important; color:#fff !important; font-weight:600 !important; border-radius:10px !important; }
    """

    with gr.Blocks(css=css) as demo:
        gr.HTML(f"""
        <div id="app-header">
          <div class="logos"><img src="{CERTIN_LOGO}" alt="CERT-In"/></div>
          <div id="app-title">IPSec Tunnel AI Agent POC</div>
          <div class="logos"><img src="{REDHAT_LOGO}" alt="Red Hat"/></div>
        </div>
        """)

        summary_md = gr.Markdown(label="Summary", elem_id="summary-box")
        actions_code = gr.Code(label="Proposed Actions (JSON)", language="json")
        approved_code = gr.Code(label="Approved Actions (JSON)", language="json")

        summary_state = gr.State("")
        actions_state = gr.State("")

        with gr.Row():
            with gr.Column(scale=3):
                approve = gr.Textbox(placeholder="Type Y / N", label="Approval", lines=1)
                submit = gr.Button("Submit")
                submit.click(
                    handleApproval,
                    inputs=[approve, summary_state, actions_state],
                    outputs=[summary_md, actions_code, approved_code, summary_state, actions_state],
                )

            analyze_btn = gr.Button("Analyze Firewall VPN", variant="primary", scale=1)
            analyze_btn.click(
                analyzeFW,
                inputs=None,
                outputs=[summary_md, actions_code, approved_code, summary_state, actions_state],
                api_name="analyse",
            )

    demo.launch()

if __name__ == "__main__":
    main()
