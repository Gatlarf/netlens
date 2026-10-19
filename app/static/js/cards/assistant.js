import { api, get, post } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const MODE_TEXT = { read: "Read only: looks, explains and diagnoses", change: "Can also change settings (one request at a time, in the audit log)" };

// The text the person pastes into their AI assistant. The token is in it, so it is shown once and only here.
function promptFor(token, mode) {
  const base = location.origin;
  return [
    `You are helping me set up and look after my Netlens network monitor at ${base}.`,
    `First read your instructions: send GET ${base}/api/assistant/guide with the header "Authorization: Bearer ${token}". Then follow them exactly.`,
    `Your token is in ${mode} mode. Ask me before you change anything. Do not ask me to paste passwords into this chat.`,
  ].join("\n");
}

function fill(card, state) {
  clear(card);
  card.appendChild(h("h3", {}, "AI assistant"));
  card.appendChild(h("p", { class: "hint" },
    "An AI assistant outside Netlens (Claude, ChatGPT, a local model with tools) calls Netlens to help you set it up and change it later, or to find out why something is red. " +
    "It works through the normal API with a token of its own and reads a guide written for language models. It never sees stored passwords and cannot reach users, backups, sharing links, single sign-on, remote sessions or the licence. " +
    "A read-only token can only look. A token that may change settings can change one thing at a time, is told to ask you first, and every change is written to the audit log under the token's name."));
  card.appendChild(h("p", { class: "hint" },
    "Anything you paste into an AI service leaves your network. Use an assistant you trust, keep the token secret, and delete it when the job is done."));

  if (!state.tokens.length) {
    card.appendChild(h("p", { class: "hint" }, "No assistant tokens yet."));
  } else {
    const table = h("table", { class: "table" }, h("thead", {}, h("tr", {}, ["Name", "May", "Made", "Last used", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const t of state.tokens) {
      const del = h("button", { class: "btn danger", type: "button" }, "Delete");
      del.addEventListener("click", async () => {
        if (!window.confirm(`Delete the token "${t.name}"? The assistant using it loses access at once.`)) return;
        try { await api(`/api/users/${t.user_id}/tokens/${t.id}`, { method: "DELETE" }); toast("Token deleted", "success"); fill(card, await get("/api/assistant")); }
        catch (err) { toast(err.message || "Could not delete the token", "error"); }
      });
      body.appendChild(h("tr", {}, h("td", {}, h("strong", {}, t.name)), h("td", {}, t.mode === "change" ? "look and change" : "look only"), h("td", {}, fmtTime(t.created)), h("td", {}, t.last_used ? fmtTime(t.last_used) : "never"), h("td", {}, del)));
    }
    table.appendChild(body);
    card.appendChild(table);
  }

  const form = h("form", { class: "edit-form" });
  const name = h("input", { type: "text", maxlength: "60", value: "AI assistant", required: true });
  const mode = h("select", {}, h("option", { value: "read" }, MODE_TEXT.read), h("option", { value: "change", disabled: !state.change_allowed }, MODE_TEXT.change + (state.change_allowed ? "" : " (needs a licence or the free trial)")));
  const result = h("div", {});
  form.append(h("h3", {}, "New token"), h("div", { class: "field" }, h("label", {}, "Name"), name), h("div", { class: "field" }, h("label", {}, "What it may do"), mode),
    h("button", { class: "btn primary", type: "submit" }, "Create token and instructions"), result);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await post("/api/assistant/token", { name: name.value, mode: mode.value });
      const text = h("textarea", { rows: "6", readonly: true, "aria-label": "Instructions for the assistant" }, promptFor(r.token, r.mode));
      const copy = h("button", { class: "btn", type: "button" }, "Copy");
      copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(text.value); toast("Copied", "success"); } catch { text.select(); } });
      clear(result);
      result.append(h("p", { class: "warn-text" }, "Paste this into your AI assistant now. The token is shown only once; if you lose it, delete it and make a new one."), text, copy,
        h("p", { class: "hint" }, "An assistant that cannot make web requests can be given the guide instead: open /api/assistant/guide in this browser while signed in and paste its text."));
      const list = await get("/api/assistant");
      state.tokens = list.tokens;
    } catch (err) { toast(err.message || "Could not make the token", "error"); }
  });
  card.appendChild(form);
}

export async function buildAssistantCard() {
  const card = h("div", { class: "card" });
  fill(card, await get("/api/assistant"));
  return card;
}
