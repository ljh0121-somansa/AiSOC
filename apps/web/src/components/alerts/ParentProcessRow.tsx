'use client';

import React from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ParentProcessStatus } from '@/lib/alertView';
import { alertsApi } from '@/lib/api';
import { getParentProcessStatus } from '@/lib/alertView';

// ParentProcessRow
// =================
//
// One-row lazy parent-process lookup on the alert-detail page. It mirrors the
// ExplainDrawer retry pattern exactly (no SWR), because the backend returns a
// single `ParentProcessResponse` envelope and the caller already has the alert
// in memory — there is nothing to cache or refocus-revalidate.
//
// Behaviour contract (see docs/edr-parent-process-lazy-loading-spec):
//
//   * Resolves immediately when a snapshot is already present on the alert
//     (`viewModel.parentProcess` is non-loading); otherwise fires
//     `alertsApi.getProcess` with skeleton loading and cancels on unmount.
//
//   * Rendered states:
//       - resolved        — "<name> (PID: <pid>)", hover tip with
//                           path / start / entity / fetched;
//       - not_found       — message + "[다시 조회]" with a 5s cooldown;
//       - unavailable     — message + "[다시 시도]";
//       - no_parent       — "부모 정보 없음";
//       - not_applicable  — row is hidden (render nothing).
//
//   * Plain text only (`span` / `code`); never `href` or
//     `dangerouslySetInnerHTML`. Control + bidi characters are stripped, UUIDs
//     are shown truncated with the full value available on hover and copied on
//     click. `shouldRetryOnError` is effectively false: a fetch failure degrades
//     to the unavailable state and emits no error banner.

/** Localized strings. The web console has no i18n framework, so this is a
 *  small inline dictionary mirroring the existing hardcoded-Korean convention
 *  while still offering an English render path. */
const messages = {
  ko: {
    parentProcess: '부모 프로세스',
    resolvedName: (name: string, pid: number | null | undefined) =>
      pid == null ? name : `${name} (PID: ${pid})`,
    notFound: '부모 프로세스를 확인할 수 없습니다 (단축 ID)',
    unavailable: '프로세스 조회를 확인할 수 없습니다',
    noParent: '부모 정보 없음',
    loadingSkeleton: '=====',
    requery: '다시 조회',
    retry: '다시 시도',
    cooldown: '({n}초 후 이용 가능)',
    copy: 'UUID 복사',
    copied: '복사됨',
    tipExecutable: '실행 파일',
    tipPath: '경로',
    tipPid: 'PID',
    tipStartedAt: '시작 시각',
    tipFetchedAt: '조회 시각',
    tipEntity: 'Entity ID',
    tipName: '프로세스 이름',
  },
  en: {
    parentProcess: 'Parent process',
    resolvedName: (name: string, pid: number | null | undefined) =>
      pid == null ? name : `${name} (PID: ${pid})`,
    notFound: 'Parent process unknown (short ID)',
    unavailable: 'Unable to resolve parent process',
    noParent: 'No parent process',
    loadingSkeleton: '=====',
    requery: 'Re-query',
    retry: 'Retry',
    cooldown: '({n}s)',
    copy: 'Copy UUID',
    copied: 'Copied',
    tipExecutable: 'Executable',
    tipPath: 'Path',
    tipPid: 'PID',
    tipStartedAt: 'Started at',
    tipFetchedAt: 'Fetched at',
    tipEntity: 'Entity ID',
    tipName: 'Process name',
  },
} as const;

export type Locale = keyof typeof messages;

export interface ParentProcessRowProps {
  /** Alert id, used as the fetch path (`/api/v1/alerts/{id}/parent-process`). */
  alertId: string;
  /** Pre-mapped status from `buildAlertView`. When loading/absent the row
   *  performs a lookup; when present it renders that state immediately. */
  status?: ParentProcessStatus | null;
  locale?: Locale;
}

const COOLDOWN_MS = 5_000;

// Strip ASCII control characters and the Unicode bidi / zero-width formatting
// marks that can hide or reorder rendered text (process names, IDs).
function sanitizeControl(text: string): string {
  return text
    // ASCII + C1 control characters, then Bidi and zero-width formatting marks
    // that can reorder or hide rendered process names / IDs.
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '')
    .replace(
      /[\u061C\u070F\u180E\u200A-\u200F\u2028-\u202F\u205F-\u206F\uFEFF\u2060-\u2065]/g,
      '',
    );
}

function shortId(id: string | null | undefined): string {
  if (!id) return '';
  return `${id.slice(0, 8)}…`;
}

export function ParentProcessRow({
  alertId,
  status: initialStatus,
  locale = 'ko',
}: ParentProcessRowProps): React.ReactNode {
  const msg = messages[locale] ?? messages.ko;
  const [status, setStatus] = useState<ParentProcessStatus | null>(
    initialStatus ?? null,
  );
  const abortRef = useRef<AbortController | null>(null);
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [remaining, setRemaining] = useState(0);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // A snapshot is usable (not loading) when it carries a concrete status. When
  // it is loading/absent the effect below performs the lookup.
  const snapshotPresent =
    status != null && status.status !== 'loading' && status.status !== null;

  useEffect(() => {
    if (snapshotPresent) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus((prev) => (prev ? prev : { status: 'loading', parent_lookup: null }));
    void alertsApi
      .getProcess(alertId, controller.signal)
      .then((response) => {
        if (controller.signal.aborted) return;
        // Reuse the same mapper so the fetched response folds onto the exact
        // same UI enum as the snapshot path.
        setStatus(getParentProcessStatus(response, 'eligible'));
      })
      .catch(() => {
        // shouldRetryOnError:false — no banner. Degrade to unavailable so the
        // row still shows a retry affordance.
        if (controller.signal.aborted) return;
        setStatus(getParentProcessStatus({ status: 'unavailable' }, 'eligible'));
      });
    return () => {
      controller.abort();
    };
  }, [alertId, snapshotPresent]);

  // Cooldown countdown so the retry button shows live seconds remaining.
  useEffect(() => {
    if (cooldownUntil === 0) {
      setRemaining(0);
      return;
    }
    const tick = () => {
      const r = Math.ceil((cooldownUntil - Date.now()) / 1000);
      setRemaining(r <= 0 ? 0 : r);
    };
    tick();
    const id = setInterval(tick, 250);
    return () => clearInterval(id);
  }, [cooldownUntil]);

  const handleRetry = useCallback(() => {
    if (remaining > 0) return;
    setCooldownUntil(Date.now() + COOLDOWN_MS);
    // Reset to null so the fetch effect re-runs with skeleton loading.
    setStatus(null);
  }, [remaining]);

  const handleCopy = useCallback(
    (value: string | null | undefined, key: string) => {
      const cleaned = sanitizeControl(value ?? '');
      if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
        return;
      }
      navigator.clipboard
        .writeText(cleaned)
        .then(() => {
          setCopiedKey(key);
          setTimeout(() => setCopiedKey(null), 1500);
        })
        .catch(() => {
          /* clipboard rejected — leave key as-is, no banner */
        });
    },
    [],
  );

  const inCooldown = remaining > 0;

  // not_applicable: hide the row entirely.
  if (status?.status === 'not_applicable') return null;

  // No resolved data yet (first mount before fetch, or explicitly null): show a
  // skeleton pulsing bar until the fetch resolves.
  if (status == null || status.status === 'loading') {
    return (
      <div className="flex items-center gap-2 text-sm">
        <span className="font-medium text-gray-400">{msg.parentProcess}:</span>
        <span
          aria-busy="true"
          aria-label={msg.parentProcess}
          className="inline-block bg-gray-800/70 rounded animate-pulse px-2 py-0.5 font-mono text-gray-500"
        >
          {msg.loadingSkeleton}
        </span>
      </div>
    );
  }

  const code = (child: React.ReactNode, title?: string): React.ReactNode => (
    <code title={title} className="text-gray-200 break-all">
      {child}
    </code>
  );

  switch (status.status) {
    case 'resolved': {
      const name = status.name || '';
      const tipLines = [
        status.executable != null
          ? `${msg.tipExecutable}: ${status.executable}`
          : null,
        status.started_at != null ? `${msg.tipStartedAt}: ${status.started_at}` : null,
        status.pid != null ? `${msg.tipPid}: ${status.pid}` : null,
        status.fetched_at != null
          ? `${msg.tipFetchedAt}: ${status.fetched_at}`
          : null,
        status.entity_id != null ? `${msg.tipEntity}: ${status.entity_id}` : null,
      ].filter((line): line is string => line != null);
      return (
        <div className="flex items-center gap-2 text-sm">
          <span className="font-medium text-gray-400">{msg.parentProcess}:</span>
          <span
            title={tipLines.join('\n')}
            className="text-gray-200"
            data-testid="parent-process-resolved"
          >
            {msg.resolvedName(name, status.pid)}
          </span>
          {status.entity_id != null && (
            <button
              type="button"
              className="text-xs text-gray-500 hover:text-gray-300 underline-offset-2 hover:underline"
              title={`${msg.tipEntity}: ${status.entity_id}`}
              onClick={() => handleCopy(status.entity_id, `entity-${status.entity_id}`)}
            >
              {copiedKey === `entity-${status.entity_id}` ? msg.copied : shortId(status.entity_id)}
            </button>
          )}
        </div>
      );
    }

    case 'not_found':
    case 'unavailable':
      return (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium text-gray-400">{msg.parentProcess}:</span>
          <span
            className="text-gray-500"
            data-testid={status.status === 'not_found' ? 'parent-process-not-found' : 'parent-process-unavailable'}
          >
            {status.status === 'not_found' ? msg.notFound : msg.unavailable}
          </span>
          {status.entity_id != null && (
            <span className="text-gray-500">
              ({msg.tipEntity}: {shortId(status.entity_id)})
            </span>
          )}
          <button
            type="button"
            disabled={inCooldown}
            onClick={handleRetry}
            className="px-2 py-0.5 text-xs bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-gray-300 border border-gray-700"
            data-testid="parent-process-retry"
          >
            {status.status === 'not_found' ? msg.requery : msg.retry}
            {inCooldown ? ` ${msg.cooldown.replace('{n}', String(remaining))}` : ''}
          </button>
        </div>
      );

    case 'no_parent':
      return (
        <div className="flex items-center gap-2 text-sm">
          <span className="font-medium text-gray-400">{msg.parentProcess}:</span>
          <span className="text-gray-500" data-testid="parent-process-no-parent">
            {msg.noParent}
          </span>
        </div>
      );

    default:
      return null;
  }
}
