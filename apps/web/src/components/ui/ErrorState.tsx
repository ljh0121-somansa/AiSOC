import { clsx } from 'clsx';
import type { ReactNode } from 'react';

interface ErrorStateProps {
  title?: string;
  description?: string;
  error?: unknown;
  onRetry?: () => void;
  action?: ReactNode;
  className?: string;
}

function formatError(error: unknown): string | undefined {
  if (!error) return undefined;
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/**
 * Surface a backend/network failure clearly so the analyst can act.
 *
 * Hides raw exceptions behind a friendly title, but exposes the
 * underlying message to power users when present (helpful for support).
 */
export function ErrorState({
  title,
  description,
  error,
  onRetry,
  action,
  className,
}: ErrorStateProps) {
  const detail = formatError(error);
  const is403 =
    (error && typeof error === 'object' && 'status' in error && (error as any).status === 403) ||
    (detail && (detail.includes('403') || detail.includes('Forbidden')));

  const displayTitle = is403
    ? '접근 권한이 없습니다 (Access Denied)'
    : (title || 'Something went wrong');

  const displayDesc = is403
    ? '이 화면을 조회하거나 수행할 수 있는 권한이 부여되지 않았습니다. 관리자에게 역할(Role) 및 권한 부여를 요청하세요.'
    : (description || "We couldn't load this view. Try again or check the service status.");

  return (
    <div
      className={clsx(
        'rounded-xl border border-amber-500/30 bg-amber-500/5 px-6 py-8 text-center',
        !is403 && 'border-red-500/30 bg-red-500/5',
        className,
      )}
      role="alert"
    >
      <div
        className={clsx(
          'mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-500/15 text-amber-400',
          !is403 && 'bg-red-500/15 text-red-400',
        )}
      >
        {is403 ? (
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
        ) : (
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
            />
          </svg>
        )}
      </div>
      <h3 className={clsx('text-base font-semibold', is403 ? 'text-amber-200' : 'text-red-200')}>
        {displayTitle}
      </h3>
      <p className={clsx('mx-auto mt-1 max-w-md text-sm', is403 ? 'text-amber-300/80' : 'text-red-300/70')}>
        {displayDesc}
      </p>
      {detail && (
        <pre className={clsx('mx-auto mt-4 max-w-xl overflow-x-auto rounded-md bg-black/30 px-3 py-2 text-left font-mono text-xs', is403 ? 'text-amber-300/80' : 'text-red-300/80')}>
          {detail}
        </pre>
      )}
      <div className="mt-5 flex items-center justify-center gap-3">
        {onRetry && (
          <button
            onClick={onRetry}
            className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm font-medium text-red-200 transition-colors hover:bg-red-500/20"
          >
            Retry
          </button>
        )}
        {action}
      </div>
    </div>
  );
}
