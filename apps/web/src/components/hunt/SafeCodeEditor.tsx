'use client';

/**
 * SafeCodeEditor — a single editor widget used across the app that renders
 * Monaco when the local Monaco runtime mounts, and degrades gracefully to a
 * full-featured <textarea> when it cannot.
 *
 * WHY THIS EXISTS
 * ---------------
 * The Monaco runtime is shipped in `apps/web/public/monaco/vs/` and pointed
 * at with `apps/web/src/lib/monaco.ts` (`loader.config({ paths: { vs: '/monaco/vs' } })`).
 * That makes Monaco load zero external bytes, which is what makes the editor
 * work in a closed / air-gapped network.
 *
* But loading Monaco is inherently fragile in a browser: even with local
* assets, a memory-constrained or very old browser may still fail to mount
* the editor. When Monaco never mounts within a short window, this component
* degrades to a usable <textarea> instead of leaving the user a frozen block.
*
 * CONTRACT (matches across Monaco + fallback so callers never branch on which
 * one is active):
 *   - value: string              (controlled current contents)
 *   - onChange: (value) => void  (single source of truth stays with the parent)
 *   - language: Lang             (syntax binding shown to the user)
 *   - disabled?: boolean
 *
 * The editor never holds state of its own. Whatever is mounted, `value` and
 * `onChange` are wired identically, so the parent's state is the single truth
 * and a render swap is transparent.
 */

import { lazy, useCallback, useEffect, useRef, useState, Suspense } from 'react';

import type { Lang } from './HuntView';

// Load Monaco lazily so SSR never touches it and production bundles only pay
// for it on pages that actually render the editor.
const MonacoLazy = lazy(() => import('./MonacoEditor'));

interface EditorProps {
  /** Controlled current contents. */
  value: string;
  /** Invoked with the new value whenever the user types / pastes / deletes. */
  onChange: (value: string) => void;
  language: Lang;
  /** Optional height (CSS length string). Defaults to 280px. */
  height?: string;
  /** Optional disabled state. */
  disabled?: boolean;
  /** Optional run shortcut handler (e.g. Cmd/Ctrl+Enter). */
  onRunShortcut?: () => void;
  /** Optional id for labels/accessibility. */
  inputId?: string;
  /** Optional className wrapper. */
  className?: string;
  /** Optional placeholder. Defaults to "Enter a query…". */
  placeholder?: string;
  /**
   * Fired by the underlying Monaco editor when it has mounted. SafeCodeEditor
   * uses this as the only positive signal that Monaco is alive, so it can keep
   * the <textarea> fallback truly failure-driven.
   */
  onMount?: (editor: unknown) => void;
}

/**
 * Guard: if Monaco still hasn't mounted after this many ms, show the fallback
 * so the UI is never frozen indefinitely on a low-end browser.
 */
const FALLBACK_TIMEOUT_MS = 3000;

// Maps the app's language ids to the grammar Monaco actually understands.
// Monaco has no dedicated 'kql'/'lucene'/'esql' grammars, so we bind the
// query languages to the closest available ones.
const MONACO_LANGUAGE: Record<Lang, string> = {
  kql: 'plaintext',
  lucene: 'plaintext',
  sql: 'sql',
  esql: 'sql',
};

// User-facing labels for accessibility text on the fallback <textarea>.
const LABELS: Record<Lang, string> = {
  kql: 'KQL',
  lucene: 'Lucene',
  sql: 'SQL',
  esql: 'ES|QL',
};

function EditorInner({
  value,
  onChange,
  language,
  height,
  disabled,
  onRunShortcut,
  inputId,
  placeholder,
  onMount,
}: EditorProps) {
  const [fallback, setFallback] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The single positive signal that Monaco really mounted: its onMount callback.
  // When it fires we clear the safety timer, so the <textarea> fallback triggers
  // only when Monaco never mounts within the window (a slow/unmountable editor,
  // or a blocked CDN) — never for a working editor that merely took longer.
  const onMonacoMount = useCallback((editor: unknown) => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
    onMount?.(editor);
  }, [onMount]);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    timer.current = setTimeout(() => setFallback(true), FALLBACK_TIMEOUT_MS);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  if (fallback) {
    return (
      <FallbackEditor
        value={value}
        onChange={onChange}
        language={language}
        height={height}
        disabled={disabled}
        onRunShortcut={onRunShortcut}
        inputId={inputId}
        placeholder={placeholder}
      />
    );
  }

  return (
    <Suspense fallback={<div className="h-16 rounded bg-slate-800/40 animate-pulse" />}>
      <MonacoLazy
        value={value}
        onChange={onChange}
        language={MONACO_LANGUAGE[language]}
        height={height}
        disabled={disabled}
        onMount={onMonacoMount}
      />
    </Suspense>
  );
}

interface FallbackEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: Lang;
  height?: string;
  disabled?: boolean;
  onRunShortcut?: () => void;
  inputId?: string;
  placeholder?: string;
}

/**
 * Full-featured textarea fallback used when Monaco can't mount.
 *
 * Deliberately supports the same interactions analysts rely on:
 *   - Tab key inserts 2 spaces instead of moving focus (code editors do this)
 *   - Cmd/Ctrl+Enter triggers onRunShortcut (run hunt)
 *   - Preserves the value/onChange contract exactly as Monaco does
 *   - Reads the same "language" for an accessible label
 *
 * This keeps the /hunt page fully usable (type, edit, run, save) even if the
 * heavier editor is unavailable.
 */
function FallbackEditor({
  value,
  onChange,
  language,
  height,
  disabled,
  onRunShortcut,
  inputId,
  placeholder,
}: FallbackEditorProps) {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      // Enter → run hunt (with Cmd/Ctrl) instead of newline
      if (
        e.key === 'Enter' &&
        (e.metaKey || e.ctrlKey) &&
        typeof onRunShortcut === 'function'
      ) {
        e.preventDefault();
        onRunShortcut();
        return;
      }
      // Tab → insert 2 spaces instead of moving focus
      if (e.key === 'Tab') {
        e.preventDefault();
        const target = e.currentTarget as HTMLTextAreaElement;
        const { selectionStart, selectionEnd, value: v } = target;
        const next = v.slice(0, selectionStart) + '  ' + v.slice(selectionEnd);
        onChange(next);
        // Move caret after the inserted spaces after render
        requestAnimationFrame(() => {
          target.selectionStart = target.selectionEnd = selectionStart + 2;
        });
      }
    },
    [onChange, onRunShortcut],
  );

  const label = LABELS[language];

  return (
    <div
      className="flex h-full w-full flex-col overflow-hidden rounded-lg border border-slate-700/70 bg-[#0d1117]"
      aria-label={`${label} query editor`}
    >
      <textarea
        id={inputId}
        value={value}
        disabled={disabled}
        readOnly={disabled}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={placeholder ?? `Enter ${label} query…`}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="soft"
        className="h-full w-full resize-y rounded bg-transparent px-3 py-2 font-mono text-sm leading-relaxed text-slate-100 placeholder:text-slate-500 focus:outline-none disabled:opacity-60"
        style={height ? { height } : undefined}
        aria-label={`${label} query editor`}
      />
    </div>
  );
}

export function SafeCodeEditor(props: EditorProps) {
  const { height = '280px', language } = props;

  return (
    <div className="relative h-full w-full overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/40">
      <EditorInner
        {...props}
        height={height}
        language={language}
      />
    </div>
  );
}
