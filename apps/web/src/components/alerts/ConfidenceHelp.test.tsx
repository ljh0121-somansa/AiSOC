import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  explainFactor,
  FACTOR_METADATA,
  OVERALL_CONFIDENCE_HELP,
} from './confidenceHelp';
import { ConfidenceExplainability, ConfidenceFactorBar } from './AlertDetailView';
import type { ConfidenceFactor } from '@/lib/api';

describe('confidenceHelp logic', () => {
  it('correctly explains negative severity penalty (low)', () => {
    const factor: ConfidenceFactor = {
      factor: 'severity',
      label: 'Alert severity',
      value: 'low',
      contribution: -0.5,
      weight: 0.2,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.impact).toBe('penalty');
    expect(exp.contributionText).toBe('-0.50');
    expect(exp.reason).toContain('-0.50');
    expect(exp.reason).toContain('penalized');
    expect(exp.observedText).toBe('LOW severity');
  });

  it('correctly explains negative severity penalty (info)', () => {
    const factor: ConfidenceFactor = {
      factor: 'severity',
      label: 'Alert severity',
      value: 'info',
      contribution: -1.0,
      weight: 0.2,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.reason).toContain('-1.00 penalty');
  });

  it('correctly explains positive severity boost (critical)', () => {
    const factor: ConfidenceFactor = {
      factor: 'severity',
      label: 'Alert severity',
      value: 'critical',
      contribution: 1.0,
      weight: 0.2,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(false);
    expect(exp.impact).toBe('boost');
    expect(exp.contributionText).toBe('+1.00');
    expect(exp.reason).toContain('+1.00');
  });

  it('correctly explains negative ML anomaly (< 0.50)', () => {
    const factor: ConfidenceFactor = {
      factor: 'ml_anomaly',
      label: 'ML anomaly score',
      value: '0.20',
      contribution: -0.6,
      weight: 0.18,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.reason).toContain('below the 0.50 baseline');
    expect(exp.reason).toContain('normal baseline patterns');
  });

  it('correctly explains negative MITRE coverage (0 techniques)', () => {
    const factor: ConfidenceFactor = {
      factor: 'mitre_coverage',
      label: 'MITRE technique coverage',
      value: '0 techniques',
      contribution: -0.4,
      weight: 0.14,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.reason).toContain('-0.40 penalty');
    expect(exp.reason).toContain('could not be verified');
  });

  it('correctly explains negative threat intelligence (no TI match)', () => {
    const factor: ConfidenceFactor = {
      factor: 'threat_intel',
      label: 'Threat-intel match',
      value: 'no TI match',
      contribution: -0.3,
      weight: 0.16,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.reason).toContain('-0.30');
    expect(exp.reason).toContain('No matching indicators');
  });

  it('correctly explains negative IOC density (0 fields)', () => {
    const factor: ConfidenceFactor = {
      factor: 'ioc_density',
      label: 'IOC density',
      value: '0 populated fields',
      contribution: -0.6,
      weight: 0.06,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.reason).toContain('-0.60');
    expect(exp.reason).toContain('insufficient investigative context');
  });

  it('handles custom / fallback factors gracefully without throwing', () => {
    const factor: ConfidenceFactor = {
      factor: 'custom_signal',
      label: 'Custom signal',
      value: 'anomaly detected',
      contribution: -0.25,
      weight: 0.1,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(true);
    expect(exp.contributionText).toBe('-0.25');
    expect(exp.reason).toContain('penalty of -0.25');
  });

  it('contains comprehensive metadata and overall formula help', () => {
    expect(OVERALL_CONFIDENCE_HELP.formula).toContain('Clamp(Σ (Weight_i × Contribution_i) + 0.50, 0, 1)');
    expect(OVERALL_CONFIDENCE_HELP.negativeExplanation).toContain('Why can factor values be negative?');
    expect(FACTOR_METADATA.severity.rules.length).toBeGreaterThanOrEqual(4);
  });

  it('correctly normalizes string and numeric factor values from raw API rationale', () => {
    const rawRationale = [
      { factor: 'severity', label: 'Alert severity', value: 'low', contribution: -0.5, weight: 0.2 },
      { factor: 'mitre_coverage', label: 'MITRE technique coverage', value: '3 techniques', contribution: 0.6, weight: 0.14 },
      { factor: 'ml_anomaly', label: 'ML anomaly score', value: 0.85, contribution: 0.7, weight: 0.18 },
    ];
    const normalized = rawRationale.map((f) => ({
      factor: String(f.factor ?? ''),
      label: String(f.label ?? ''),
      value: typeof f.value === 'number' ? f.value : String(f.value ?? ''),
      contribution: Number(f.contribution ?? 0),
      weight: Number(f.weight ?? 0),
    }));

    expect(normalized[0].value).toBe('low');
    expect(normalized[1].value).toBe('3 techniques');
    expect(normalized[2].value).toBe(0.85);
  });

  it('does not confuse 10 techniques with 0 techniques for MITRE coverage', () => {
    const factor: ConfidenceFactor = {
      factor: 'mitre_coverage',
      label: 'MITRE technique coverage',
      value: '10 techniques',
      contribution: 1.0,
      weight: 0.14,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(false);
    expect(exp.impact).toBe('boost');
    expect(exp.reason).toContain('10 techniques mapped');
    expect(exp.reason).not.toContain('No validated MITRE');
  });

  it('does not confuse 10 populated fields with 1 field for IOC density', () => {
    const factor: ConfidenceFactor = {
      factor: 'ioc_density',
      label: 'IOC density',
      value: '10 populated fields',
      contribution: 1.0,
      weight: 0.06,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(false);
    expect(exp.impact).toBe('boost');
    expect(exp.reason).toContain('rich investigative context');
    expect(exp.reason).not.toContain('neutral baseline');
  });

  it('handles empty string value in ML anomaly without turning it into 0', () => {
    const factor: ConfidenceFactor = {
      factor: 'ml_anomaly',
      label: 'ML anomaly score',
      value: '',
      contribution: 0.5,
      weight: 0.18,
    };
    const exp = explainFactor(factor);
    expect(exp.isPenalty).toBe(false);
    expect(exp.observedText).toBe('Not specified');
  });
});

describe('ConfidenceFactorBar and ConfidenceExplainability UI Components', () => {
  const sampleFactors: ConfidenceFactor[] = [
    {
      factor: 'severity',
      label: 'Alert severity',
      value: 'low',
      contribution: -0.5,
      weight: 0.2,
    },
    {
      factor: 'threat_intel',
      label: 'Threat-intel match',
      value: 'no TI match',
      contribution: -0.3,
      weight: 0.16,
    },
    {
      factor: 'mitre_coverage',
      label: 'MITRE technique coverage',
      value: '0 techniques',
      contribution: -0.4,
      weight: 0.14,
    },
    {
      factor: 'ml_anomaly',
      label: 'ML anomaly score',
      value: '0.85',
      contribution: 0.7,
      weight: 0.18,
    },
  ];

  it('renders negative score values, penalty badges, and info trigger buttons', () => {
    render(
      <ConfidenceExplainability
        label="low"
        score={0.32}
        rationale={sampleFactors}
      />
    );

    // Section title
    expect(screen.getByText('Detection Confidence')).toBeInTheDocument();
    expect(screen.getByText('Why this score')).toBeInTheDocument();

    // Check penalty contribution display
    expect(screen.getByText('-0.50')).toBeInTheDocument();
    expect(screen.getByText('-0.30')).toBeInTheDocument();
    expect(screen.getByText('-0.40')).toBeInTheDocument();
    expect(screen.getByText('+0.70')).toBeInTheDocument();

    // Penalty badges
    const penaltyBadges = screen.getAllByText('Penalty');
    expect(penaltyBadges.length).toBe(3);
    expect(screen.getByText('Boost')).toBeInTheDocument();

    // Observed conditions visible in bar
    expect(screen.getByText('LOW severity')).toBeInTheDocument();
    expect(screen.getByText('no TI match')).toBeInTheDocument();
  });

  it('opens factor tooltip with scoring rules and reason on click', async () => {
    const user = userEvent.setup();
    render(<ConfidenceFactorBar factor={sampleFactors[0]} />);

    const severityHelpBtn = screen.getByRole('button', {
      name: /Show scoring rules and conditions for Alert severity/i,
    });
    expect(severityHelpBtn).toBeInTheDocument();

    await user.click(severityHelpBtn);

    // Tooltip should appear
    expect(screen.getByRole('tooltip')).toBeInTheDocument();
    expect(screen.getByText(/Low severity is penalized by -0.50/i)).toBeInTheDocument();
    expect(screen.getByText('Scoring Condition Matrix')).toBeInTheDocument();
    expect(screen.getByText(/Penalized to reduce routine fatigue/i)).toBeInTheDocument();
  });

  it('opens section header formula help tooltip explaining why scores can be negative', async () => {
    const user = userEvent.setup();
    render(
      <ConfidenceExplainability
        label="low"
        score={0.32}
        rationale={sampleFactors}
      />
    );

    const formulaHelpBtn = screen.getByRole('button', {
      name: /Explain detection confidence formula and scoring conditions/i,
    });
    expect(formulaHelpBtn).toBeInTheDocument();

    await user.click(formulaHelpBtn);

    // Formula tooltip
    expect(screen.getByText('Detection Confidence Score Formula')).toBeInTheDocument();
    expect(screen.getByText(/Why can score values be negative\?/i)).toBeInTheDocument();
    expect(screen.getByText(/pull the score below 50% to prevent false positives/i)).toBeInTheDocument();
  });

  it('closes pinned tooltip when Escape key is pressed', async () => {
    const user = userEvent.setup();
    render(<ConfidenceFactorBar factor={sampleFactors[0]} />);

    const severityHelpBtn = screen.getByRole('button', {
      name: /Show scoring rules and conditions for Alert severity/i,
    });
    await user.click(severityHelpBtn);
    expect(screen.getByRole('tooltip')).toBeInTheDocument();

    // Press Escape
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });

  it('closes pinned tooltip when clicking outside', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <div data-testid="outside-area">Outside</div>
        <ConfidenceFactorBar factor={sampleFactors[0]} />
      </div>
    );

    const severityHelpBtn = screen.getByRole('button', {
      name: /Show scoring rules and conditions for Alert severity/i,
    });
    await user.click(severityHelpBtn);
    expect(screen.getByRole('tooltip')).toBeInTheDocument();

    // Click outside
    await user.click(screen.getByTestId('outside-area'));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });
});
