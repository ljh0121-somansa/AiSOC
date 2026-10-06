'use client';

/**
 * MonacoEditor — thin wrapper around `@monaco-editor/react` bound to the
 * project's bundled Monaco runtime (see `apps/web/src/lib/monaco.ts`).
 *
 * The @monaco-editor/loader config that points Monaco at /monaco/vs (a local,
 * same-origin asset bundle) is set once when apps/web/src/lib/monaco.ts is
 * first imported. This wrapper simply renders the editor and syncs the value
 * into Monaco's model on every external change.
 *
 * If Monaco ever fails to mount (e.g. a constrained browser), SafeCodeEditor
 * swaps in its <textarea> fallback after a timeout. See SafeCodeEditor.tsx.
 */

import Core, { type OnMount } from '@monaco-editor/react';

interface Props {
  value: string;
  onChange: (value: string) => void;
  language: string;
  height?: string;
  disabled?: boolean;
  /**
   * Fired when the underlying Monaco editor has mounted. SafeCodeEditor uses
   * this as the only positive signal that Monaco is alive and clears its
   * fallback timer. `monaco` is unused by callers.
   */
  onMount?: OnMount;
}

export default function MonacoEditor({
  value,
  onChange,
  language,
  height,
  disabled,
  onMount,
}: Props) {
  return (
    <Core
      language={language.toLowerCase()}
      value={value}
      onChange={(v) => onChange(v ?? '')}
      onMount={onMount}
      theme="vs-dark"
      height={height ?? '280px'}
      options={{
        minimap: { enabled: false },
        fontSize: 13,
        fontFamily: "'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
        lineNumbers: 'on',
        scrollBeyondLastLine: false,
        renderLineHighlight: 'line',
        smoothScrolling: true,
        tabSize: 2,
        wordWrap: 'on',
        readOnly: !!disabled,
      }}
    />
  );
}
