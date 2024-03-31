document.body.parentElement.addEventListener("click", (event) => {
  let activeDetails = null;
  let element = event.target;
  while (element != null) {
    if (element.tagName != "DETAILS") {
      element = element.parentElement;
      continue;
    }
    activeDetails = element;
    break;
  }
  for (const dataAutocloseDetails of document.querySelectorAll("details[data-autoclose-details]")) {
    if (dataAutocloseDetails.open && dataAutocloseDetails != activeDetails) {
      dataAutocloseDetails.open = false;
    }
  }
});

for (const dataDismissAlert of document.querySelectorAll("[data-dismiss-alert]")) {
  dataDismissAlert.addEventListener("click", function() {
    let parentElement = dataDismissAlert.parentElement;
    while (parentElement != null) {
      const role = parentElement.getAttribute("role");
      if (role != "alert") {
        parentElement = parentElement.parentElement;
        continue;
      }
      parentElement.style.transition = "opacity 100ms linear";
      parentElement.style.opacity = "0";
      setTimeout(function() { parentElement.style.display = "none" }, 100);
      return;
    }
  });
}

for (const dataGoBack of document.querySelectorAll("[data-go-back]")) {
  if (dataGoBack.tagName != "A") {
    continue;
  }
  dataGoBack.addEventListener("click", function(event) {
    if (document.referrer && history.length > 2 && !event.ctrlKey && !event.metaKey) {
      event.preventDefault();
      history.back();
    }
  });
}

for (const dataDisableClickSelection of document.querySelectorAll("[data-disable-click-selection]")) {
  dataDisableClickSelection.addEventListener("mousedown", function(event) {
    // https://stackoverflow.com/a/43321596
    if (event.detail > 1) {
      event.preventDefault();
    }
  });
}

for (const dataPaste of document.querySelectorAll("[data-paste]")) {
  let name = "";
  let validExt = new Set();
  try {
    const obj = JSON.parse(dataPaste.getAttribute("data-paste"));
    if (obj.name) {
      name = obj.name;
    }
    if (obj.ext) {
      for (let i = 0; i < obj.ext.length; i++) {
        validExt.add(obj.ext[i]);
      }
    }
  } catch (e) {
    console.error(e);
    continue;
  }

  let form = null;
  let element = dataPaste.parentElement;
  while (element != null) {
    if (element instanceof HTMLFormElement) {
      form = element;
      break;
    }
    element = element.parentElement;
  }
  if (!form) {
    continue;
  }
  const input = form.elements[name];
  if (!(input instanceof HTMLInputElement) || input.type != "file") {
    continue;
  }

  dataPaste.addEventListener("paste", function(event) {
    event.preventDefault();
    if (event.clipboardData.files.length == 0) {
      dataPaste.value = "no files in clipboard";
      setTimeout(function() { dataPaste.value = "" }, 800);
      return;
    }
    let dataTransfer = new DataTransfer();
    let invalidCount = 0;
    for (let i = 0; i < input.files.length; i++) {
      const file = input.files.item(i);
      dataTransfer.items.add(file);
    }
    const files = [];
    for (let i = 0; i < event.clipboardData.files.length; i++) {
      const file = event.clipboardData.files.item(i);
      const n = file.name.lastIndexOf(".");
      const ext = n < 0 ? "" : file.name.substring(n);
      if (!validExt.has(ext)) {
        invalidCount++;
        continue;
      }
      files.push(file);
    }
    files.sort(function(a, b) {
      if (a.lastModified == b.lastModified) {
        return 0;
      }
      if (a.lastModified < b.lastModified) {
        return -1;
      }
      return 1;
    });
    for (const file of files) {
      dataTransfer.items.add(file);
    }
    if (invalidCount > 0) {
      dataPaste.value = `${invalidCount} invalid file${invalidCount == 1 ? "" : "s"}`;
      setTimeout(function() { dataPaste.value = "" }, 800);
    }
    input.files = dataTransfer.files;
  });
}

for (const [index, dataEditor] of document.querySelectorAll("[data-editor]").entries()) {
  const config = new Map();
  try {
    let obj = JSON.parse(dataEditor.getAttribute("data-editor") || "{}");
    for (const [key, value] of Object.entries(obj)) {
      config.set(key, value);
    }
  } catch (e) {
    console.error(e);
    continue;
  }

  const textarea = dataEditor.querySelector("textarea");
  if (!textarea) {
    continue;
  }

  // Auto-resize textarea to fit content.
  textarea.style.overflow = "hidden";
  textarea.style.height = "auto";
  textarea.style.height = `${textarea.scrollHeight}px`;
  textarea.addEventListener("input", function() {
    textarea.style.height = "auto";
    textarea.style.height = `${textarea.scrollHeight}px`;
  });

  // Locate the parent form that houses the textarea.
  let form;
  let element = textarea.parentElement;
  while (element != null) {
    if (element instanceof HTMLFormElement) {
      form = element;
      break;
    }
    element = element.parentElement;
  }
  if (!form) {
    continue;
  }

  // Determine the file extension.
  let ext = "";
  if (config.has("ext")) {
    ext = config.get("ext");
  } else if (config.has("extElementName")) {
    const extElementName = config.get("extElementName");
    const extElement = form.elements[extElementName];
    if (extElement) {
      ext = extElement.value;
    }
  }

  // Ctrl-s/Cmd-s to submit.
  textarea.addEventListener("keydown", function(event) {
    if (navigator.userAgent.includes("Macintosh")) {
      if (!event.metaKey || event.key != "s") {
        return;
      }
    } else {
      if (!event.ctrlKey || event.key != "s") {
        return;
      }
    }
    event.preventDefault();
    form.dispatchEvent(new Event("submit"));
    form.submit();
  });

  // Restore cursor position from localStorage.
  const position = Number(localStorage.getItem(`textareaposition:${window.location.pathname}:${index}`));
  if (position && position <= textarea.value.length) {
    textarea.setSelectionRange(position, position);
  }

  // Configure word wrap.
  let wordwrapEnabled = localStorage.getItem(`wordwrap:${window.location.pathname}:${index}`);
  if (wordwrapEnabled == null) {
    if (ext == ".html" || ext == ".css" || ext == ".js") {
      wordwrapEnabled = "false";
    } else {
      wordwrapEnabled = "true";
    }
  }
  if (wordwrapEnabled == "true") {
    textarea.style.whiteSpace = "pre-wrap";
    textarea.style.overflow = "hidden";
    textarea.style.height = "auto";
    textarea.style.height = `${textarea.scrollHeight}px`;
  } else {
    textarea.style.whiteSpace = "pre";
    textarea.style.overflow = "auto";
    textarea.style.height = "auto";
    textarea.style.height = `${textarea.scrollHeight}px`;
  }
  if (config.has("wordwrapCheckboxID")) {
    const wordwrapCheckboxID = config.get("wordwrapCheckboxID");
    const wordwrapInput = document.getElementById(wordwrapCheckboxID);
    if (wordwrapInput) {
      wordwrapInput.checked = wordwrapEnabled == "true";
      wordwrapInput.addEventListener("change", function() {
        if (wordwrapInput.checked) {
          localStorage.setItem(`wordwrap:${window.location.pathname}:${index}`, "true");
          textarea.style.whiteSpace = "pre-wrap";
          textarea.style.overflow = "hidden";
          textarea.style.height = "auto";
          textarea.style.height = `${textarea.scrollHeight}px`;
        } else {
          localStorage.setItem(`wordwrap:${window.location.pathname}:${index}`, "false");
          textarea.style.whiteSpace = "pre";
          textarea.style.overflow = "auto";
          textarea.style.height = "auto";
          textarea.style.height = `${textarea.scrollHeight}px`;
        }
      });
    }
  }

  // On form submit, save the cursor position to localStorage.
  form.addEventListener("submit", function() {
    localStorage.setItem(`textareaposition:${window.location.pathname}:${index}`, textarea.selectionStart.toString());
  });

  if (ext != ".html" && ext != ".css" && ext != ".js") {
    if (config.get("scrollIntoView")) {
      textarea.blur();
      textarea.focus();
      textarea.blur();
    }
  }
}
