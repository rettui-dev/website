// The Downloads page: reads /api/releases (which the server keeps from GitHub) and draws one
// table of files for each project. All text is set with textContent, never as HTML, and a link is
// only used when it points at github.com.
(() => {
  const FALLBACK = [
    ["rettui-dev/rettui", "https://github.com/rettui-dev/rettui/releases"],
    ["rettui-dev/rngit-rs", "https://github.com/rettui-dev/rngit-rs/releases"],
  ];
  const projects = document.getElementById("projects");
  const status = document.getElementById("downloads-status");

  const el = (tag, props = {}, ...kids) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "text") node.textContent = v;
      else if (k === "class") node.className = v;
      else node.setAttribute(k, v);
    }
    for (const kid of kids) node.append(kid);
    return node;
  };

  const safeUrl = (u) => (typeof u === "string" && u.startsWith("https://github.com/") ? u : null);
  const link = (url, text) => {
    const href = safeUrl(url);
    if (!href) return document.createTextNode(text);
    return el("a", { href, rel: "noopener noreferrer", text });
  };

  const size = (n) => {
    if (!Number.isFinite(n)) return "";
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  };

  const age = (seconds) => {
    if (seconds < 90) return "a minute";
    if (seconds < 5400) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 172800) return `${Math.round(seconds / 3600)} hours`;
    return `${Math.round(seconds / 86400)} days`;
  };

  const row = (asset) => {
    const platform = el("td", { "data-label": "Platform" }, asset.label);
    if (asset.kind) platform.append(" ", el("span", { class: "dim", text: `(${asset.kind})` }));
    const file = el("td", { "data-label": "File", class: "file" }, link(asset.url, asset.name));
    const bytes = el("td", { "data-label": "Size", class: "num", text: size(asset.size) });
    const sum = el("td", { "data-label": "SHA-256" });
    if (asset.sha256) {
      const title = asset.checksumSource === "file" ? "From the release's checksum file. Click to copy." : "Click to copy.";
      sum.append(el("button", {
        type: "button", class: "hash", "data-copy": asset.sha256, "data-copy-status": "copy-status", title,
        "aria-label": `Copy the SHA-256 of ${asset.name}`, text: asset.sha256,
      }));
    } else {
      sum.append(el("span", { class: "dim", text: "no checksum published" }));
    }
    for (const cell of [platform, file, bytes, sum]) cell.setAttribute("role", "cell");
    return el("tr", { role: "row" }, platform, file, bytes, sum);
  };

  const section = (p) => {
    const id = `project-${p.repo.replace(/[^a-z0-9]+/gi, "-")}`;
    const box = el("section", { class: "project", "aria-labelledby": id }, el("h2", { id }, link(p.url, p.repo)));
    const releasesLink = el("p", {}, link(p.releasesUrl, "All releases on GitHub"));
    if (p.status === "ok" && p.release) {
      const r = p.release;
      const date = r.publishedAt ? r.publishedAt.slice(0, 10) : null;
      const meta = el("p", { class: "release-meta" }, el("b", { class: "num", text: r.tag }));
      if (date) meta.append(` released ${date}. `);
      meta.append(link(r.url, "Release notes and GitHub release"));
      box.append(meta);
      if (p.stale) {
        box.append(el("p", { class: "note-inline", text: `GitHub could not be reached just now, so this is the list from ${age(p.ageSeconds)} ago.` }));
      }
      if (r.assets.length === 0) {
        box.append(el("p", { text: "This release has no files attached." }));
      } else {
        const table = el("table", { class: "dl", role: "table" }, el("caption", { class: "sr-only", text: `Files of ${p.repo} ${r.tag}` }));
        table.append(el("thead", { role: "rowgroup" }, el("tr", { role: "row" }, ...["Platform", "File", "Size", "SHA-256"].map((h) => el("th", { scope: "col", role: "columnheader", text: h })))));
        table.append(el("tbody", { role: "rowgroup" }, ...r.assets.map(row)));
        box.append(el("div", { class: "table-wrap" }, table));
      }
    } else if (p.status === "none") {
      box.append(el("p", { text: "No release has been published yet." }));
    } else if (p.status === "loading") {
      box.append(el("p", { text: "The release list is still loading. Try again in a minute." }));
    } else {
      box.append(el("p", { text: "The releases could not be loaded from GitHub just now." }));
    }
    box.append(releasesLink);
    return box;
  };

  const failed = () => {
    status.textContent = "The release list could not be loaded. Use GitHub directly:";
    projects.replaceChildren(el("ul", {}, ...FALLBACK.map(([name, url]) => el("li", {}, link(url, `${name} releases`)))));
  };

  let tries = 0;
  const load = () => {
    fetch("/api/releases", { cache: "no-store", headers: { Accept: "application/json" } })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("bad status"))))
      .then((data) => {
        if (!data || !Array.isArray(data.projects)) throw new Error("bad data");
        projects.replaceChildren(...data.projects.map(section));
        status.textContent = "";
        // The server fetches in the background; right after a start there may be nothing yet.
        if (data.projects.some((p) => p.status === "loading") && ++tries < 6) setTimeout(load, 5000);
      })
      .catch(failed);
  };
  load();
})();
