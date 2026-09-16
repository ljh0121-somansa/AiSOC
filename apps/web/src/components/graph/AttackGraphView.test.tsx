/**
 * AttackGraphView — kind normalization + backend-error surfacing.
 *
 * These are the two behaviors the live-Neo4j plan (2026-09-16) restored:
 *
 *   1. The backend emits an ingest `kind` (e.g. `"endpoint"`), but the frontend
 *      only has color/shape maps for a small visual vocabulary (`host`, `user`,
 *      `ip`, ...). The view must normalize ingest kinds onto that vocabulary so
 *      every node gets a real shape instead of silently falling to the default.
 *      `normalizeKind` is exported so the mapping is unit-testable directly.
 *
 *   2. A rejected `getOverview` / `getMitreCoverage` must surface a real
 *      `ErrorState`, not a swallowed empty graph.
 *
 * SWR is mocked at the module boundary (mirrors FunnelKpiBar.test.tsx) so we can
 * drive loading / data / error states without touching the real fetcher.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrLoading = vi.hoisted(() => new Set<string>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    if (swrLoading.has(k)) {
      return { data: undefined, error: undefined, isLoading: true };
    }
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
    };
  },
}));

// cytoscape needs a 2D canvas context that jsdom does not provide, so mock
// it: the graph canvas becomes an inert container and cy.on / cy.destroy are
// no-ops. The parts under test here are kind normalization + error surfacing,
// not cytoscape rendering.
vi.mock('cytoscape', () => {
  const noop = vi.fn();
  return {
    __esModule: true,
    default: vi.fn(() => ({
      on: noop,
      destroy: noop,
    })),
  };
});

vi.mock('@/lib/api', () => ({
  __esModule: true,
  graphApi: {
    getOverview: vi.fn(),
    getMitreCoverage: vi.fn(),
  },
}));

import { AttackGraphView, normalizeKind } from './AttackGraphView';
import { graphApi } from '@/lib/api';

const GRAPH_KEY = 'attack-graph';
const MITRE_KEY = 'mitre-coverage';

const SAMPLE_GRAPH = {
  source: 'neo4j',
  generatedAt: '2026-09-16T10:00:00.000Z',
  nodes: [{ id: 'e1', label: 'win-host-1', kind: 'endpoint', riskScore: 60 }],
  edges: [],
};

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrLoading.clear();
  vi.restoreAllMocks();

  const overview = vi.fn(async () => SAMPLE_GRAPH);
  const mitre = vi.fn(async () => ({
    tactics: ['Lateral Movement'],
    cells: [
      {
        techniqueId: 'T1021',
        techniqueName: 'Remote Desktop',
        tactic: 'Lateral Movement',
        detections: 1,
        alerts: 2,
        intensity: 0.4,
      },
    ],
    generatedAt: '2026-09-16T10:00:00.000Z',
  }));
  graphApi.getOverview = overview;
  graphApi.getMitreCoverage = mitre;
});

describe('normalizeKind', () => {
  it('maps ingest labels onto the visual vocabulary', () => {
    expect(normalizeKind('endpoint')).toBe('host');
    expect(normalizeKind('serviceaccount')).toBe('user');
    expect(normalizeKind('networkpath')).toBe('ip');
    expect(normalizeKind('detection')).toBe('technique');
    expect(normalizeKind('alert')).toBe('alert');
    expect(normalizeKind('resource')).toBe('asset');
  });

  it('falls back to asset for unknown kinds', () => {
    expect(normalizeKind('some-unknown-label')).toBe('asset');
  });
});

describe('AttackGraphView error surfacing', () => {
  it('renders a real ErrorState when getOverview rejects', async () => {
    // swr mock reads swrErrors at render time; drive it directly.
    swrErrors.set(GRAPH_KEY, new Error('503 Service Unavailable'));

    render(<AttackGraphView />);

    expect(screen.getByText("Couldn't load graph")).toBeInTheDocument();
    expect(screen.queryByText('No graph yet')).not.toBeInTheDocument();
  });

  it('renders a real ErrorState when getMitreCoverage rejects', async () => {
    swrErrors.set(MITRE_KEY, new Error('500'));

    render(<AttackGraphView />);

    expect(
      screen.getByText("Couldn't load MITRE coverage"),
    ).toBeInTheDocument();
    expect(screen.queryByText('커버리지 데이터 없음')).not.toBeInTheDocument();
  });
});

describe('AttackGraphView rendering', () => {
  it('renders the graph + MITRE panels when live data is present', () => {
    swrData.set(GRAPH_KEY, SAMPLE_GRAPH);
    swrData.set(MITRE_KEY, {
      tactics: [],
      cells: [],
      generatedAt: '2026-09-16T10:00:00.000Z',
    });

    render(<AttackGraphView />);

    expect(screen.getByText('Attack Graph')).toBeInTheDocument();
    expect(screen.getByText('MITRE ATT&CK Coverage')).toBeInTheDocument();
    // The cytoscape canvas renders node labels onto its own surface (not DOM
    // text), so verify the graph panel is active by the *absence* of the empty
    // state.
    expect(screen.queryByText('No graph yet')).not.toBeInTheDocument();
  });

  it('shows a relational-fallback badge when source is relational', () => {
    swrData.set(GRAPH_KEY, { ...SAMPLE_GRAPH, source: 'relational' });
    swrData.set(MITRE_KEY, {
      tactics: [],
      cells: [],
      generatedAt: '2026-09-16T10:00:00.000Z',
    });

    render(<AttackGraphView />);

    expect(screen.getByText('Relational fallback')).toBeInTheDocument();
  });

  it('renders an empty state when no graph and no backend error', () => {
    swrData.set(GRAPH_KEY, {
      source: 'neo4j',
      generatedAt: '2026-09-16T10:00:00.000Z',
      nodes: [],
      edges: [],
    });
    swrData.set(MITRE_KEY, {
      tactics: [],
      cells: [],
      generatedAt: '2026-09-16T10:00:00.000Z',
    });

    render(<AttackGraphView />);

    expect(screen.getByText('No graph yet')).toBeInTheDocument();
  });
});
