// Clicking an address marked data-copy copies it instead of following the
// link (a browser can't open rrc:// itself). Without a clipboard, the link
// works as normal.
document.addEventListener("click", (e) => {
  const a = e.target instanceof Element ? e.target.closest("a[data-copy]") : null;
  if (!a || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  if (!navigator.clipboard) return;
  e.preventDefault();
  const note = a.parentElement && a.parentElement.querySelector(".copied");
  navigator.clipboard.writeText(a.dataset.copy).then(
    () => {
      if (!note) return;
      note.textContent = "Copied";
      setTimeout(() => { note.textContent = ""; }, 1500);
    },
    () => { window.location.href = a.href; },
  );
});
