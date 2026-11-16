import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { EditorView, basicSetup } from "codemirror";
import { useEffect, useRef } from "react";

// Colours come from the theme tokens, so the editor follows light and dark like the rest.
const theme = EditorView.theme({
  "&": { color: "var(--text)", backgroundColor: "var(--surface)", fontSize: "12.5px", height: "100%" },
  ".cm-content": { fontFamily: "'JetBrains Mono Variable', ui-monospace, monospace", caretColor: "var(--accent)" },
  ".cm-gutters": { backgroundColor: "var(--surface-2)", color: "var(--text-muted)", border: "none" },
  ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--accent) 6%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--accent) 10%, transparent)" },
  "&.cm-focused": { outline: "2px solid var(--accent)", outlineOffset: "-2px" },
  ".cm-scroller": { overflow: "auto" },
});

// The default highlight colours are made for white pages (keywords in #0000cc read at 1.6:1 on the
// dark surface). These use the theme tokens, which meet 4.5:1 in both themes (D062).
const highlight = HighlightStyle.define([
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: "var(--text)" },
  { tag: [tags.keyword, tags.bool, tags.null, tags.atom], color: "var(--accent)" },
  { tag: [tags.number], color: "var(--sev-high)" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--allow)" },
  { tag: [tags.comment, tags.lineComment], color: "var(--text-muted)", fontStyle: "italic" },
  { tag: [tags.punctuation, tags.separator, tags.squareBracket, tags.brace], color: "var(--text-muted)" },
]);

/**
 * CodeMirror 6 with YAML highlighting. The text lives in React state; the editor reports edits up
 * and takes changes made elsewhere (the threshold sliders, a reload) without losing the cursor.
 */
export function YamlEditor({ value, onChange, label }: { value: string; onChange: (text: string) => void; label: string }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const report = useRef(onChange);
  report.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    const editor = new EditorView({
      doc: value,
      parent: host.current,
      extensions: [
        basicSetup,
        yaml(),
        theme,
        syntaxHighlighting(highlight),
        EditorView.contentAttributes.of({ "aria-label": label }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) report.current(update.state.doc.toString());
        }),
      ],
    });
    view.current = editor;
    return () => {
      editor.destroy();
      view.current = null;
    };
    // Built once; later values arrive through the effect below.
  }, []);

  useEffect(() => {
    const editor = view.current;
    if (!editor) return;
    const current = editor.state.doc.toString();
    if (current !== value) editor.dispatch({ changes: { from: 0, to: current.length, insert: value } });
  }, [value]);

  return <div ref={host} className="h-[560px] overflow-hidden rounded-card border border-border" />;
}
