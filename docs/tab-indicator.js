const tab = document.getElementById("tab-sigs");
const summary = document.getElementById("summary");

if (tab && summary) {
  tab.setAttribute("aria-describedby", "summary");
  const sync = () => {
    const m = /\bis-(ok|bad|warn|pending|idle)\b/.exec(summary.className);
    tab.dataset.state = m?.[1] === "ok" ? "ok" : m?.[1] === "bad" ? "bad" : "none";
  };
  new MutationObserver(sync).observe(summary, { attributes: true, attributeFilter: ["class"] });
  sync();
}
