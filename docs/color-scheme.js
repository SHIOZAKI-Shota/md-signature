// Loaded as a blocking script in <head>: applies the saved colour scheme before first paint to avoid a flash.
try {
  document.querySelector('meta[name="color-scheme"]').content = localStorage.getItem("mdsig-color-scheme") || "light dark";
} catch (e) {}
