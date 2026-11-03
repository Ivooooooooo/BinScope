






try {
  const stored = localStorage.getItem("binscope.theme");
  if (stored === "light" || stored === "dark") {
    document.documentElement.dataset.theme = stored;
  }
} catch {
  

}
