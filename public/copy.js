// Click to copy. An address marked data-copy (a link, as rrc:// can't be opened by a browser) or
// a button with data-copy (the text) or data-copy-from (the id of an element whose text is
// copied) puts the text on the clipboard and says "Copied" in a role=status element: the one named
// by data-copy-status, else the first .copied beside it. Without a clipboard, a link works as
// normal and a button selects the text so it can be copied by hand.
(() => {
  const say = (note, message) => {
    if (!note) return;
    note.textContent = message;
    clearTimeout(note.copyTimer);
    note.copyTimer = setTimeout(() => { note.textContent = ""; }, message === "Copied" ? 1500 : 6000);
  };

  const noteFor = (el) => {
    const id = el.dataset.copyStatus;
    if (id) return document.getElementById(id);
    return el.parentElement && el.parentElement.querySelector(".copied");
  };

  const textFor = (el) => {
    if (el.dataset.copy !== undefined) return el.dataset.copy;
    const source = el.dataset.copyFrom && document.getElementById(el.dataset.copyFrom);
    return source ? source.textContent : null;
  };

  const select = (el) => {
    const source = el.dataset.copyFrom && document.getElementById(el.dataset.copyFrom);
    if (!source || !window.getSelection) return false;
    const range = document.createRange();
    range.selectNodeContents(source);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    return true;
  };

  document.addEventListener("click", (e) => {
    const el = e.target instanceof Element ? e.target.closest("a[data-copy], button[data-copy], button[data-copy-from]") : null;
    if (!el || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    const isLink = el.tagName === "A";
    const text = textFor(el);
    if (text === null) return;
    const note = noteFor(el);
    const fallback = () => {
      if (isLink) window.location.href = el.href;
      else say(note, select(el) ? "Selected. Press Ctrl+C to copy." : "Could not copy.");
    };
    if (!navigator.clipboard) {
      if (!isLink) fallback();
      return;
    }
    e.preventDefault();
    navigator.clipboard.writeText(text).then(() => say(note, "Copied"), fallback);
  });
})();
