import { describe, it, expect } from 'vitest';

describe('Confidence score normalization logic', () => {
  const normalizePct = (score?: number) =>
    typeof score === 'number'
      ? Math.max(0, Math.min(100, Math.round(score > 1 ? score : score * 100)))
      : null;

  const normalizeScore = (score?: number) =>
    typeof score === 'number'
      ? (score > 1 ? score / 100 : score).toFixed(2)
      : null;

  it('normalizes integer 0-100 percentage from production backend', () => {
    // 66 from PostgreSQL alerts.confidence
    expect(normalizePct(66)).toBe(66);
    expect(normalizeScore(66)).toBe('0.66');

    // 100% max
    expect(normalizePct(100)).toBe(100);
    expect(normalizeScore(100)).toBe('1.00');

    // 0% min
    expect(normalizePct(0)).toBe(0);
    expect(normalizeScore(0)).toBe('0.00');
  });

  it('normalizes 0.0-1.0 float ratio from mock data or direct fusion endpoint', () => {
    // 0.66 ratio
    expect(normalizePct(0.66)).toBe(66);
    expect(normalizeScore(0.66)).toBe('0.66');

    // 0.78 ratio from mock data
    expect(normalizePct(0.78)).toBe(78);
    expect(normalizeScore(0.78)).toBe('0.78');

    // 1.0 ratio
    expect(normalizePct(1.0)).toBe(100);
    expect(normalizeScore(1.0)).toBe('1.00');
  });

  it('handles undefined or null gracefully', () => {
    expect(normalizePct(undefined)).toBeNull();
    expect(normalizeScore(undefined)).toBeNull();
  });

  it('clamps out-of-bounds values safely', () => {
    expect(normalizePct(150)).toBe(100);
    expect(normalizePct(-10)).toBe(0);
  });
});
