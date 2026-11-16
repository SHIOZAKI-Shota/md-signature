const select = document.getElementById("mk-method");
const panes = [...document.querySelectorAll(".mk-pane[data-mk]")];
const KEY = "mdsig-key-method";

if (select && panes.length) {
  const show = (v) => {
    for (const p of panes) p.hidden = p.dataset.mk !== v;
  };
  try {
    const saved = localStorage.getItem(KEY);
    if (saved && panes.some((p) => p.dataset.mk === saved)) select.value = saved;
  } catch {}
  show(select.value);
  select.addEventListener("change", () => {
    show(select.value);
    try {
      localStorage.setItem(KEY, select.value);
    } catch {}
  });
}
