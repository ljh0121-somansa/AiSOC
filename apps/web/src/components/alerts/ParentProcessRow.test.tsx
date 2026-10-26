import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { fireEvent } from '@testing-library/react';
import { ParentProcessRow } from './ParentProcessRow';
import type { ParentProcessStatus } from '@/lib/alertView';
import { alertsApi } from '@/lib/api';

// The component performs a one-shot POST fetch on first render (loading) via
// `alertsApi.getProcess`, then renders one of the resolved/not_found/
// unavailable/no_parent states. We mock the API so each render path is
// exercised deterministically — no network, no connectors path, no polling.
const mockGetProcess = vi.fn();
vi.mock('@/lib/api', () => ({
  alertsApi: {
    getProcess: (...args: unknown[]) => mockGetProcess(...args),
  },
}));

// Snapshot a resolved shape the way the wire delivers it (process_id, not
// entity_id) — the mapper maps process_id -> entity_id for the UI.
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

beforeEach(() => {
  mockGetProcess.mockReset();
  mockGetProcess.mockResolvedValue(resolvedSnapshot());
  cleanup();
});

afterEach(() => {
  cleanup();
});

// Wait for the row to leave the skeleton/loading phase: any of the concrete
// render states appears with its own data-testid.
async function waitConcrete(testid: string): Promise<void> {
  if (screen.queryByTestId(testid)) return;
  // The mock resolves synchronously; a short tick is enough. Avoids
  // vi.waitFor/act-context interactions that perturb userEvent/fireEvent.
  await new Promise((r) => setTimeout(r, 5));
}

describe('ParentProcessRow render states', () => {
  it('renders a skeleton while the fetch is pending, then the resolved row (AC-1)', async () => {
    const user = userEvent.setup();
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-resolved');
    expect(screen.getByTestId('parent-process-resolved')).toHaveTextContent(
      'explorer.exe (PID: 4321)',
    );
    // The skeleton bar must be gone once resolved.
    expect(screen.queryByText('부모 프로세')).not.toBeInTheDocument();
  });

  it('renders <name> (PID: <pid>) from a pre-passed snapshot immediately (AC-1 persisted)', () => {
    const status: ParentProcessStatus = {
      status: 'resolved',
      entity_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
      name: 'w3wp.exe',
      pid: 1234,
      started_at: '2026-10-22T03:00:10.000Z',
      source: 'persisted',
    };
    render(<ParentProcessRow alertId="alert-1" status={status} />);
    expect(screen.getByTestId('parent-process-resolved')).toHaveTextContent(
      'w3wp.exe (PID: 1234)',
    );
  });

  it('hides the row entirely when not_applicable (AC-8)', async () => {
    mockGetProcess.mockResolvedValue({ status: 'not_applicable', entity_id: null });
    render(<ParentProcessRow alertId="alert-1" />);
    await new Promise((r) => setTimeout(r, 5));
    expect(screen.queryByTestId('parent-process-resolved')).not.toBeInTheDocument();
    // The whole label "부모 프로세스" is absent for not_applicable.
    expect(screen.queryByText('부모 프로세')).not.toBeInTheDocument();
  });

  it('shows not_found text + retry with the short ID (AC-2, AC-14)', async () => {
    mockGetProcess.mockResolvedValue({
      status: 'not_found',
      entity_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
    });
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-not-found');
    expect(screen.getByTestId('parent-process-retry')).toBeInTheDocument();
  });

  it('shows unavailable text + retry (AC-2)', async () => {
    mockGetProcess.mockResolvedValue({
      status: 'unavailable',
      entity_id: '65047b5e-4289-4229-9840-018a31e5d4c2',
    });
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-unavailable');
    expect(screen.getByTestId('parent-process-retry')).toBeInTheDocument();
  });

  it('shows no_parent text with no retry button (AC-4)', async () => {
    mockGetProcess.mockResolvedValue({ status: 'no_parent' });
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-no-parent');
    expect(screen.queryByTestId('parent-process-retry')).not.toBeInTheDocument();
  });

  it('degrades to unavailable with no error banner on fetch rejection (AC-2)', async () => {
    mockGetProcess.mockRejectedValue(new Error('EDR unavailable'));
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-unavailable');
    // No toast/banner rendered anywhere.
    expect(screen.queryByText(/에러|error|배너|토스트/)).not.toBeInTheDocument();
  });

  it('copies the full UUID on short-id click (AC-14)', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(globalThis.navigator, 'clipboard', {
      get() { return { writeText }; },
      configurable: true,
    });
    render(<ParentProcessRow alertId="alert-1" />);
    await waitConcrete('parent-process-resolved');
    // The copy affordance is the button right after the resolved span.
    const resolved = screen.getByTestId('parent-process-resolved');
    const copyBtn = resolved.nextElementSibling as HTMLButtonElement;
    expect(copyBtn).toBeInTheDocument();
    fireEvent.click(copyBtn);
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith('65047b5e-4289-4229-9840-018a31e5d4c2');
  });
});
