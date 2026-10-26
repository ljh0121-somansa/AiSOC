import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { DetectionBasisSection } from './AlertTemplateSections';
import type { ParentProcessStatus } from '@/lib/alertView';
import { normalAlert } from '@/lib/alertView.fixtures';

// ParentProcessRow (embedded in the section) fires `alertsApi.getProcess`
// when `parentProcess` is loading/absent. We mock the API so each render
// path is deterministic — no network.
const mockGetProcess = vi.fn();
vi.mock('@/lib/api', () => ({
  alertsApi: {
    getProcess: (...args: unknown[]) => mockGetProcess(...args),
  },
}));

function resolvedSnapshot(pid = 4321): unknown {
  return {
    status: 'resolved',
    process_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
    name: 'explorer.exe',
    pid,
    started_at: '2026-10-22T03:00:10.000Z',
    source: 'edr_lookup',
  };
}

function tick(): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, 5);
  return promise;
}

beforeEach(() => {
  mockGetProcess.mockReset();
  mockGetProcess.mockResolvedValue(resolvedSnapshot());
  cleanup();
});

afterEach(() => {
  cleanup();
});

const loadingStatus: ParentProcessStatus = {
  status: 'loading',
  parent_lookup: 'eligible',
};

describe('DetectionBasisSection parent-process row (On-Demand Parent Process Lazy Loading)', () => {
  it('shows a pulsing skeleton while the fetch is pending, then the resolved row (AC-LP-1)', async () => {
    const { container } = render(
      <DetectionBasisSection alert={normalAlert} alertId={normalAlert.id} parentProcess={loadingStatus} />,
    );

    // Skeleton bar is present before the mock resolves.
    expect(screen.queryByText('=====')).toBeTruthy();
    // Parent row renders as a row (not the static '미확인').
    expect(screen.getByText('부모 프로세스:')).toBeTruthy();

    await tick();

    expect(screen.queryByTestId('parent-process-resolved')).toBeTruthy();
    expect(screen.getByTestId('parent-process-resolved').textContent).toContain('explorer.exe (PID: 4321)');
    // Short-entity-id copy button rendered beside the name (AC-14).
    expect(screen.queryByText('65047b5e…')).toBeTruthy();
  });

  it('renders the resolved row immediately from a pre-mapped snapshot (AC-LP-1 persisted)', () => {
    const resolved: ParentProcessStatus = {
      status: 'resolved',
      entity_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
      name: 'explorer.exe',
      pid: 4321,
      parent_lookup: 'eligible',
    };
    render(
      <DetectionBasisSection alert={normalAlert} alertId={normalAlert.id} parentProcess={resolved} />,
    );

    // No fetch fires for a concrete snapshot.
    expect(mockGetProcess).not.toHaveBeenCalled();
    expect(screen.getByTestId('parent-process-resolved').textContent).toContain('explorer.exe (PID: 4321)');
    expect(screen.getByTestId('parent-process-resolved').getAttribute('title')).toContain('PID: 4321');
  });

  it('degrades to unavailable with a retry button and no error banner on fetch rejection (AC-LP-2)', async () => {
    mockGetProcess.mockRejectedValue(new Error('upstream 503'));
    render(
      <DetectionBasisSection alert={normalAlert} alertId={normalAlert.id} parentProcess={loadingStatus} />,
    );

    await tick();

    expect(screen.queryByTestId('parent-process-unavailable')).toBeTruthy();
    expect(screen.getByTestId('parent-process-unavailable').textContent).toContain('프로세스 조회를 확인할 수 없습니다');
    // Retry affordance present; the 5s cooldown text is not active yet.
    const retryBtn = screen.getByTestId('parent-process-retry') as HTMLButtonElement;
    expect(retryBtn.textContent).toContain('다시 시도');
    expect(retryBtn.disabled).toBe(false);
    // No error banner: the section body keeps its normal layout.
    expect(screen.queryByText('Error')).toBeNull();
  });

  it('shows not_found (EDR 404) with short entity ID and re-query button (AC-LP-2)', async () => {
    mockGetProcess.mockResolvedValue({
      status: 'not_found',
      process_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
    });
    render(
      <DetectionBasisSection alert={normalAlert} alertId={normalAlert.id} parentProcess={loadingStatus} />,
    );

    await tick();

    expect(screen.queryByTestId('parent-process-not-found')).toBeTruthy();
    expect(screen.getByTestId('parent-process-not-found').textContent).toContain('부모 프로세스를 확인할 수 없습니다 (단축 ID)');
    // Short ID rendered beside the message.
    expect(screen.getByText('(Entity ID: 65047b5e…)')).toBeTruthy();
  });

  it('hides the parent row entirely when not_applicable (AC-LP-8)', () => {
    const notApplicable: ParentProcessStatus = { status: 'not_applicable', parent_lookup: 'not_applicable' };
    render(
      <DetectionBasisSection alert={normalAlert} alertId={normalAlert.id} parentProcess={notApplicable} />,
    );

    expect(screen.queryByTestId('parent-process-resolved')).toBeNull();
    expect(screen.queryByText('부모 프로세스:')).toBeNull();
    // The rest of the section (process name / command line) still renders.
    expect(screen.getByText('cmd.exe')).toBeTruthy();
  });
});
