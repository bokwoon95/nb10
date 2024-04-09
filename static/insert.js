const dataEditor = document.querySelector("[data-editor]");
if (dataEditor) {
  const config = new Map();
  let obj = JSON.parse(dataEditor.getAttribute("data-editor") || "{}");
  for (const [key, value] of Object.entries(obj)) {
    config.set(key, value);
  }
  const textarea = dataEditor.querySelector("textarea");
  if (!textarea) {
  }
}
for (const dataInsert of document.querySelectorAll("[data-insert]")) {
  dataInsert.addEventListener("click", function() {
  });
}
