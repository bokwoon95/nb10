// To build this file:
// - Navigate to the project root where package.json is located.
// - Run npm install
// - Run ./node_modules/.bin/esbuild ./static/codemirror.ts --outfile=./static/codemirror.js --bundle --minify
import { EditorState, Prec, Compartment, TransactionSpec } from '@codemirror/state';
import { EditorView, lineNumbers, keymap } from '@codemirror/view';
import { indentWithTab, history, defaultKeymap, historyKeymap } from '@codemirror/commands';
import { indentOnInput, indentUnit, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { autocompletion, completionKeymap } from '@codemirror/autocomplete';
import { html } from "@codemirror/lang-html";
import { css } from "@codemirror/lang-css";
import { javascript } from "@codemirror/lang-javascript";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
// import { languages } from '@codemirror/language-data';

for (const [index, dataCodemirror] of document.querySelectorAll<HTMLElement>("[data-codemirror]").entries()) {
  const config = new Map<string, any>();
  try {
    let obj = JSON.parse(dataCodemirror.getAttribute("data-codemirror") || `{}`);
    for (const [key, value] of Object.entries(obj)) {
      config.set(key, value);
    }
  } catch (e) {
    console.error(e);
    continue;
  }

  // The textarea we are overriding.
  const textarea = dataCodemirror.querySelector("textarea");
  if (!textarea) {
    continue;
  }

  // Locate the parent form that houses the textarea.
  let form: HTMLFormElement | undefined;
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

  // Create the codemirror editor.
  const language = new Compartment();
  const wordwrap = new Compartment();
  const editor = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        // Basic extensions copied from basicSetup in
        // https://github.com/codemirror/basic-setup/blob/main/src/codemirror.ts.
        lineNumbers(),
        history(),
        indentUnit.of("  "),
        indentOnInput(),
        autocompletion(),
        keymap.of([
          indentWithTab,
          ...defaultKeymap,
          ...historyKeymap,
          ...completionKeymap,
        ]),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        // Dynamic settings.
        language.of([]),
        wordwrap.of([]),
        // Custom theme.
        EditorView.theme({
          "&": {
            fontSize: "11.5pt",
            border: "1px solid black",
            backgroundColor: "white",
          },
          ".cm-content": {
            fontFamily: "Menlo, Monaco, Lucida Console, monospace",
            minHeight: "16rem"
          },
          ".cm-scroller": {
            overflow: "auto",
          }
        }),
        // Custom keymaps.
        Prec.high(keymap.of([
          {
            // Ctrl-s/Cmd-s to save.
            key: "Mod-s",
            run: function(_: EditorView): boolean {
              if (form) {
                // Trigger all submit events on the form, so that the
                // codemirror instances have a chance to sychronize
                // with the textarea instances.
                form.dispatchEvent(new Event("submit"));
                // Actually submit the form.
                form.submit();
              }
              return true;
            },
          },
        ])),
      ],
    }),
  });
  function configureLanguage(ext: string) {
    switch (ext) {
      case ".html":
        editor.dispatch({
          effects: language.reconfigure(html()),
        });
        break;
      case ".css":
        editor.dispatch({
          effects: language.reconfigure(css()),
        });
        break;
      case ".js":
        editor.dispatch({
          effects: language.reconfigure(javascript()),
        });
        break;
      case ".md":
        editor.dispatch({
          effects: language.reconfigure(markdown({
            base: markdownLanguage,
            // codeLanguages: languages,
          })),
        });
        break;
      default:
        editor.dispatch({
          effects: language.reconfigure([]),
        });
        break;
    }
  }

  // Configure language.
  let ext = "";
  if (config.has("ext")) {
    ext = config.get("ext");
    if (textarea.value.length <= 50000) {
      configureLanguage(ext);
    }
  } else if (config.has("extElementName")) {
    const extElementName = config.get("extElementName");
    const extElement = form.elements[extElementName] as HTMLInputElement | HTMLSelectElement;
    if (extElement && textarea.value.length <= 50000) {
      ext = extElement.value;
      configureLanguage(extElement.value);
      extElement.addEventListener("change", function() {
        configureLanguage(extElement.value);
      });
    }
  }

  // Configure word wrap.
  let wordwrapEnabled = false;
  if (localStorage.getItem(`wordwrap:${ext}`) == "true") {
    wordwrapEnabled = true;
  } else {
    wordwrapEnabled = ext != ".html" && ext != ".css" && ext != ".js";
  }
  if (wordwrapEnabled) {
    editor.dispatch({
      effects: wordwrap.reconfigure(EditorView.lineWrapping),
    });
  }
  if (config.has("wordwrapCheckboxID")) {
    const wordwrapCheckboxID = config.get("wordwrapCheckboxID");
    const wordwrapInput = document.getElementById(wordwrapCheckboxID) as HTMLInputElement;
    if (wordwrapInput) {
      wordwrapInput.checked = wordwrapEnabled;
      wordwrapInput.addEventListener("change", function() {
        if (wordwrapInput.checked) {
          localStorage.setItem(`wordwrap:${ext}`, "true");
          editor.dispatch({
            effects: wordwrap.reconfigure(EditorView.lineWrapping),
          });
        } else {
          localStorage.setItem(`wordwrap:${ext}`, "false");
          editor.dispatch({
            effects: wordwrap.reconfigure([]),
          });
        }
      });
    }
  }

  // Replace the textarea with the codemirror editor.
  textarea.style.display = "none";
  textarea.after(editor.dom);

  const cmContent = editor.dom.querySelector<HTMLElement>(".cm-content");
  if (cmContent) {
    // If the textarea has autofocus on, shift focus to the codemirror editor.
    if (textarea.hasAttribute("autofocus")) {
      cmContent.focus();
    }
    // If the textarea has an associated label, focus the codemirror editor
    // whenever we click on it.
    if (textarea.id) {
      const textareaLabel = document.querySelector<HTMLLabelElement>(`label[for=${textarea.id}]`);
      if (textareaLabel) {
        textareaLabel.addEventListener("click", function(event) {
          event.preventDefault();
          cmContent.focus();
        });
      }
    }
  }

  // Restore cursor position from localStorage.
  const position = Number(localStorage.getItem(`${window.location.pathname}:${index}`));
  if (position && position <= textarea.value.length) {
    const transaction: TransactionSpec = {
      selection: { anchor: position, head: position },
    };
    if (config.get("scrollIntoView")) {
      transaction.effects = EditorView.scrollIntoView(position, { y: "center" });
    }
    editor.dispatch(transaction);
  }

  // On submit, synchronize the codemirror editor's contents with the
  // textarea it is paired with (before the form is submitted).
  form.addEventListener("submit", function() {
    // Save the cursor position to localStorage.
    const ranges = editor.state.selection.ranges;
    if (ranges.length > 0) {
      const position = ranges[0].from;
      localStorage.setItem(`${window.location.pathname}:${index}`, position.toString());
    }
    // Copy the codemirror editor's contents to the textarea.
    textarea.value = editor.state.doc.toString();
  });
}
