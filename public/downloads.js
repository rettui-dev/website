// The Downloads page: reads /api/releases (which the server keeps from GitHub) and draws a list of
// platforms for each project, with the main file of each first and the others folded away. All text is set with textContent, never as HTML, and a link is
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

  // One file: its name and size, and its checksum with a button that copies it. The button says "Copy",
  // and its name says what it copies, so the visible word is part of the name.
  const fileBlock = (asset) => {
    const line = el("p", { class: "file-line" }, link(asset.url, asset.name));
    if (Number.isFinite(asset.size)) line.append(el("span", { class: "num dim", text: size(asset.size) }));
    if (asset.kind) line.append(" ", el("span", { class: "dim", text: `(${asset.kind})` }));
    const sum = el("div", { class: "sum-line" });
    if (asset.sha256) {
      const where = asset.checksumSource === "file" ? " (from the release's checksum file)" : "";
      sum.append(
        el("span", { class: "sum-label", text: `SHA-256${where}` }),
        el("code", { class: "sum", text: asset.sha256 }),
        el("button", { type: "button", class: "copy-btn", "data-copy": asset.sha256, "aria-label": `Copy the SHA-256 of ${asset.name}`, text: "Copy" }),
        el("span", { class: "copied", role: "status" }),
      );
    } else {
      sum.append(el("span", { class: "dim", text: "No checksum published" }));
    }
    return el("div", { class: "file" }, line, sum);
  };

  // The files of one platform, in the order the server sends them (by platform, then by name).
  const byPlatform = (assets) => {
    const groups = new Map();
    for (const a of assets) {
      if (!groups.has(a.platform)) groups.set(a.platform, { label: a.label, files: [] });
      groups.get(a.platform).files.push(a);
    }
    return [...groups.values()];
  };

  // The file most people want for a platform: the plain rettui build, before the desktop app and the packages.
  const mainFile = (files) => files.find((f) => !f.kind) || files[0];

  const platformItem = (group) => {
    const first = mainFile(group.files);
    const rest = group.files.filter((f) => f !== first);
    const item = el("li", { class: "platform" }, el("h3", { text: group.label }), el("div", { class: "files" }, fileBlock(first)));
    if (rest.length > 0) {
      const word = rest.length === 1 ? "1 more file" : `${rest.length} more files`;
      item.append(el("details", { class: "more-files" }, el("summary", { text: `${word} for ${group.label}` }), el("div", { class: "files" }, ...rest.map(fileBlock))));
    }
    return item;
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
        box.append(el("ul", { class: "platforms", "aria-label": `Files of ${p.repo} ${r.tag}` }, ...byPlatform(r.assets).map(platformItem)));
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
