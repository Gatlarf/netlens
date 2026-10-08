import { h } from "../util.js";

// A small, safe Markdown renderer for the plugin guide: headings, paragraphs, lists, tables, code blocks,
// `inline code` and **bold**. Everything is built with textContent, never innerHTML.
function inline(text) {
  const out = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const token = m[0];
    if (token.startsWith("`")) out.push(h("code", {}, token.slice(1, -1)));
    else if (token.startsWith("**")) out.push(h("strong", {}, token.slice(2, -2)));
    else {
      const [, label, href] = /\[([^\]]+)\]\(([^)]+)\)/.exec(token);
      out.push(/^(https?:\/\/|#|\/)/.test(href) ? h("a", { href }, label) : label);
    }
    last = m.index + token.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function cells(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
}

export function renderMarkdown(markdown) {
  const root = h("div", { class: "markdown" });
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("```")) {
      const code = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) code.push(lines[i++]);
      i += 1;
      root.appendChild(h("pre", {}, h("code", {}, code.join("\n"))));
    } else if (/^#{1,4} /.test(line)) {
      const level = /^#+/.exec(line)[0].length;
      root.appendChild(h(`h${Math.min(level + 1, 5)}`, {}, inline(line.replace(/^#+ /, ""))));
      i += 1;
    } else if (line.startsWith("|") && i + 1 < lines.length && /^\|?[\s:|-]+\|?$/.test(lines[i + 1])) {
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(cells(lines[i++]));
      const table = h("table", { class: "data" });
      table.appendChild(h("thead", {}, h("tr", {}, head.map((c) => h("th", {}, inline(c))))));
      table.appendChild(h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, inline(c)))))));
      root.appendChild(table);
    } else if (/^\s*([-*]|\d+\.) /.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const list = h(ordered ? "ol" : "ul");
      while (i < lines.length && /^\s*([-*]|\d+\.) /.test(lines[i])) list.appendChild(h("li", {}, inline(lines[i++].replace(/^\s*([-*]|\d+\.) /, ""))));
      root.appendChild(list);
    } else if (line.trim() === "") {
      i += 1;
    } else {
      const para = [];
      while (i < lines.length && lines[i].trim() !== "" && !/^(```|#{1,4} |\||\s*([-*]|\d+\.) )/.test(lines[i])) para.push(lines[i++]);
      root.appendChild(h("p", {}, inline(para.join(" "))));
    }
  }
  return root;
}

export async function buildPluginGuideCard() {
  const res = await fetch("/api/plugins/guide", { credentials: "same-origin" });
  if (!res.ok) throw new Error("The plugin guide could not be loaded");
  const card = h("div", { class: "card" });
  card.appendChild(renderMarkdown(await res.text()));
  return card;
}
