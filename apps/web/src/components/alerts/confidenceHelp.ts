import type { ConfidenceFactor } from '@/lib/api';

export interface ConfidenceRule {
  condition: string;
  contribution: string;
  effect: 'boost' | 'neutral' | 'penalty';
  note?: string;
}

export interface FactorMeta {
  key: string;
  label: string;
  description: string;
  weight: number;
  baseline: string;
  rules: ConfidenceRule[];
}

export interface FactorExplanation {
  meta: FactorMeta;
  observedText: string;
  impact: 'boost' | 'neutral' | 'penalty';
  isPenalty: boolean;
  reason: string;
  contributionText: string;
  weightText: string;
}

export const FACTOR_METADATA: Record<string, FactorMeta> = {
  severity: {
    key: 'severity',
    label: 'Alert severity',
    description: 'Calculates confidence based on the inherent severity rating of the alert. Low and Info events are penalized to suppress noise.',
    weight: 0.20,
    baseline: 'Medium (0.00)',
    rules: [
      { condition: 'Critical', contribution: '+1.00', effect: 'boost', note: 'Strongest operational signal' },
      { condition: 'High', contribution: '+0.60', effect: 'boost', note: 'High operational priority' },
      { condition: 'Medium', contribution: '0.00', effect: 'neutral', note: 'Baseline neutral anchor' },
      { condition: 'Low', contribution: '-0.50', effect: 'penalty', note: 'Penalized to reduce routine fatigue' },
      { condition: 'Info', contribution: '-1.00', effect: 'penalty', note: 'Penalized as purely informational noise' },
    ],
  },
  ml_anomaly: {
    key: 'ml_anomaly',
    label: 'ML anomaly score',
    description: 'IsolationForest unsupervised anomaly detection score in [0.0, 1.0], centered on the 0.50 baseline.',
    weight: 0.18,
    baseline: '0.50 (normal baseline activity)',
    rules: [
      { condition: '> 0.50', contribution: 'Up to +1.00', effect: 'boost', note: 'Atypical behavioral deviation detected' },
      { condition: '= 0.50', contribution: '0.00', effect: 'neutral', note: 'Consistent with normal baseline' },
      { condition: '< 0.50', contribution: 'Down to -1.00', effect: 'penalty', note: 'Standard benign pattern penalizes confidence' },
    ],
  },
  ml_priority: {
    key: 'ml_priority',
    label: 'ML priority rank',
    description: 'LightGBM supervised triage priority score in [0.0, 1.0], calibrated against historical analyst actions.',
    weight: 0.18,
    baseline: '0.50 (neutral priority)',
    rules: [
      { condition: '> 0.50', contribution: 'Up to +1.00', effect: 'boost', note: 'Model predicts high escalation probability' },
      { condition: '= 0.50', contribution: '0.00', effect: 'neutral', note: 'Borderline triage priority' },
      { condition: '< 0.50', contribution: 'Down to -1.00', effect: 'penalty', note: 'Model predicts probable benign/low priority' },
    ],
  },
  mitre_coverage: {
    key: 'mitre_coverage',
    label: 'MITRE technique coverage',
    description: 'Count of validated MITRE ATT&CK techniques mapped to this detection.',
    weight: 0.14,
    baseline: '1 technique (0.00)',
    rules: [
      { condition: '0 techniques', contribution: '-0.40', effect: 'penalty', note: 'Penalized: attack technique cannot be corroborated' },
      { condition: '1 technique', contribution: '0.00', effect: 'neutral', note: 'Single isolated technique baseline' },
      { condition: '2 techniques', contribution: '+0.40', effect: 'boost', note: 'Multi-technique correlation boost' },
      { condition: '3+ techniques', contribution: '+0.60 ~ +1.00', effect: 'boost', note: 'Complex attack chain progression' },
    ],
  },
  threat_intel: {
    key: 'threat_intel',
    label: 'Threat-intel match',
    description: 'Corroboration against external threat intelligence feeds (MISP, OTX, TAXII, KEV, VirusTotal).',
    weight: 0.16,
    baseline: 'N/A (unmatched feeds penalize)',
    rules: [
      { condition: 'No match (0 feeds)', contribution: '-0.30', effect: 'penalty', note: 'Penalized: indicators uncorroborated in TI feeds' },
      { condition: '1 feed match', contribution: '+0.60', effect: 'boost', note: 'Corroborated by external intelligence feed' },
      { condition: '2+ feed matches', contribution: '+1.00', effect: 'boost', note: 'Strong multi-source TI corroboration' },
    ],
  },
  upstream_risk: {
    key: 'upstream_risk',
    label: 'Upstream vendor risk score',
    description: 'Vendor-native risk score provided directly by the source EDR/SIEM (0.0 ~ 1.0, centered on 0.50).',
    weight: 0.08,
    baseline: '0.50 (50% vendor score)',
    rules: [
      { condition: '> 0.50', contribution: 'Up to +1.00', effect: 'boost', note: 'Vendor rated as higher-risk event' },
      { condition: '= 0.50', contribution: '0.00', effect: 'neutral', note: 'Neutral vendor rating' },
      { condition: '< 0.50', contribution: 'Down to -1.00', effect: 'penalty', note: 'Low vendor risk rating reduces confidence' },
    ],
  },
  ioc_density: {
    key: 'ioc_density',
    label: 'IOC density',
    description: 'Count of populated IOC entity fields (src_ip, dst_ip, hostname, username, file_hash, domain, url).',
    weight: 0.06,
    baseline: '1 ~ 2 populated fields (0.00)',
    rules: [
      { condition: '0 fields', contribution: '-0.60', effect: 'penalty', note: 'Penalized: insufficient entity context to investigate' },
      { condition: '1 ~ 2 fields', contribution: '0.00', effect: 'neutral', note: 'Minimal entity context baseline' },
      { condition: '3 ~ 4 fields', contribution: '+0.50', effect: 'boost', note: 'Rich context for entity pivot analysis' },
      { condition: '5+ fields', contribution: '+1.00', effect: 'boost', note: 'Comprehensive multi-entity forensics available' },
    ],
  },
  institutional_memory: {
    key: 'institutional_memory',
    label: 'Institutional memory',
    description: 'Bounded historical feedback prior learned from past analyst dispositions on identical signature keys.',
    weight: 0.05,
    baseline: 'No prior history (0.00)',
    rules: [
      { condition: 'Repeated True Positive', contribution: 'Up to +1.00', effect: 'boost', note: 'Analysts consistently verified as legitimate threat' },
      { condition: 'No history', contribution: '0.00', effect: 'neutral', note: 'First-time or unclassified signature' },
      { condition: 'Repeated Benign/FP', contribution: 'Down to -1.00', effect: 'penalty', note: 'Analysts previously closed as benign noise' },
    ],
  },
  asset_criticality: {
    key: 'asset_criticality',
    label: 'Asset criticality',
    description: 'Criticality tier of the impacted asset or crown-jewel infrastructure.',
    weight: 0.10,
    baseline: 'Tier 3 (0.00)',
    rules: [
      { condition: 'Tier 1 (Mission-critical)', contribution: '+1.00', effect: 'boost', note: 'Crown-jewel asset compromise risk' },
      { condition: 'Tier 2 (High)', contribution: '+0.50', effect: 'boost', note: 'High business value asset' },
      { condition: 'Tier 3 (Standard)', contribution: '0.00', effect: 'neutral', note: 'Standard workstation/server baseline' },
      { condition: 'Tier 4 / Sandbox', contribution: '-0.50', effect: 'penalty', note: 'Isolated test environment' },
    ],
  },
};

export const OVERALL_CONFIDENCE_HELP = {
  title: 'Detection Confidence Score Formula',
  formula: 'Confidence = Clamp(Σ (Weight_i × Contribution_i) + 0.50, 0, 1) × 100%',
  summary:
    'Detection confidence starts at a 50% neutral baseline (0.50) and combines 7 weighted security signals. Each factor contributes between -1.00 and +1.00 multiplied by its weight.',
  negativeExplanation:
    'Why can factor values be negative? Factors that indicate routine noise, normal baseline behavior, or lack of corroboration (such as Low severity, 0 MITRE techniques, or no Threat Intel hits) emit negative contributions. These penalties pull the score below 50% to prevent false positives and alert fatigue.',
  bands: [
    { label: 'High', range: '≥ 70%', color: 'text-emerald-400', desc: 'Multiple corroborating signals confirm high attack probability.' },
    { label: 'Medium', range: '40% – 69%', color: 'text-amber-400', desc: 'Suspicious event requiring analyst verification.' },
    { label: 'Low', range: '< 40%', color: 'text-rose-400', desc: 'Score penalized by routine noise or absent corroboration.' },
  ],
};

export function explainFactor(factor: ConfidenceFactor): FactorExplanation {
  const meta = FACTOR_METADATA[factor.factor] ?? {
    key: factor.factor,
    label: factor.label || factor.factor,
    description: `Evaluates ${factor.label || factor.factor} for alert confidence scoring.`,
    weight: factor.weight,
    baseline: 'Neutral baseline (0.00)',
    rules: [
      { condition: 'Positive signal', contribution: '> 0.00', effect: 'boost' },
      { condition: 'Baseline', contribution: '0.00', effect: 'neutral' },
      { condition: 'Negative signal / penalty', contribution: '< 0.00', effect: 'penalty' },
    ],
  };

  const contribution = factor.contribution;
  const isPenalty = contribution < -0.001;
  const impact: 'boost' | 'neutral' | 'penalty' =
    contribution > 0.001 ? 'boost' : contribution < -0.001 ? 'penalty' : 'neutral';

  const rawVal = factor.value != null ? String(factor.value).trim() : '';
  const valLower = rawVal.toLowerCase();

  const parseNumber = (val: string): number => {
    const trimmed = val.trim();
    if (!trimmed) return NaN;
    const num = Number(trimmed);
    return Number.isNaN(num) ? NaN : num;
  };

  const parseCount = (val: string): number | null => {
    const match = val.match(/\b\d+\b/);
    return match ? parseInt(match[0], 10) : null;
  };

  let observedText = rawVal || 'Not specified';
  let reason = '';

  switch (factor.factor) {
    case 'severity': {
      observedText = rawVal ? `${rawVal.toUpperCase()} severity` : 'Unknown severity';
      if (valLower === 'critical') {
        reason = 'Critical severity indicates high-consequence impact, providing a maximum boost (+1.00).';
      } else if (valLower === 'high') {
        reason = 'High severity provides a strong confidence boost (+0.60).';
      } else if (valLower === 'medium') {
        reason = 'Medium severity serves as the neutral baseline (0.00 contribution).';
      } else if (valLower === 'low') {
        reason = 'Low severity is penalized by -0.50 to suppress noise from routine low-urgency events.';
      } else if (valLower === 'info') {
        reason = 'Informational alerts receive a -1.00 penalty because they rarely represent active attacks.';
      } else if (isPenalty) {
        reason = `Severity "${rawVal}" penalizes confidence by ${contribution.toFixed(2)}.`;
      } else {
        reason = `Severity "${rawVal}" contributes ${contribution >= 0 ? '+' : ''}${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'ml_anomaly': {
      const num = parseNumber(rawVal);
      if (!Number.isNaN(num)) {
        observedText = `Anomaly score ${num.toFixed(2)}`;
        if (num < 0.50) {
          reason = `Anomaly score (${num.toFixed(2)}) is below the 0.50 baseline, applying a ${contribution.toFixed(2)} penalty because behavior conforms to normal baseline patterns.`;
        } else if (num > 0.50) {
          reason = `Anomaly score (${num.toFixed(2)}) exceeds the 0.50 baseline, applying a +${contribution.toFixed(2)} boost for atypical behavioral deviation.`;
        } else {
          reason = 'Anomaly score is exactly at the 0.50 baseline (neutral 0.00 contribution).';
        }
      } else {
        reason = isPenalty
          ? `Below-baseline anomaly score penalized confidence by ${contribution.toFixed(2)}.`
          : `Anomaly score contributed +${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'ml_priority': {
      const num = parseNumber(rawVal);
      if (!Number.isNaN(num)) {
        observedText = `Priority score ${num.toFixed(2)}`;
        if (num < 0.50) {
          reason = `Triage priority (${num.toFixed(2)}) is below 0.50, applying a ${contribution.toFixed(2)} penalty based on historical benign patterns.`;
        } else if (num > 0.50) {
          reason = `Triage priority (${num.toFixed(2)}) exceeds 0.50, boosting confidence by +${contribution.toFixed(2)}.`;
        } else {
          reason = 'Priority score is at the 0.50 neutral baseline.';
        }
      } else {
        reason = isPenalty
          ? `Low triage priority penalized confidence by ${contribution.toFixed(2)}.`
          : `High triage priority boosted confidence by +${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'mitre_coverage': {
      const count = parseCount(valLower);
      observedText = rawVal || (count != null ? `${count} technique${count === 1 ? '' : 's'}` : '0 techniques');
      if (count === 0 || (count == null && (valLower.includes('no') || isPenalty))) {
        reason = 'No validated MITRE ATT&CK techniques mapped, resulting in a -0.40 penalty because attack tactics could not be verified.';
      } else if (count === 1) {
        reason = '1 mapped MITRE technique serves as the neutral baseline (0.00 contribution).';
      } else if (count != null && count >= 2) {
        reason = `${observedText} mapped, providing a +${contribution.toFixed(2)} boost due to multi-technique attack chain correlation.`;
      } else {
        reason = isPenalty
          ? `MITRE technique coverage penalized confidence by ${contribution.toFixed(2)}.`
          : `MITRE technique coverage contributed +${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'threat_intel': {
      observedText = rawVal || 'No TI match';
      const isNoMatch =
        valLower.includes('no ti match') ||
        valLower.includes('no match') ||
        valLower === 'none' ||
        valLower === '0' ||
        valLower.startsWith('0 ');
      if (isNoMatch || isPenalty) {
        reason = 'No matching indicators found in threat intelligence feeds (MISP, OTX, KEV, VT), penalizing confidence by -0.30.';
      } else {
        reason = `Corroborated by threat intelligence feeds (${rawVal}), boosting confidence by +${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'upstream_risk': {
      const num = parseNumber(rawVal);
      if (!Number.isNaN(num)) {
        observedText = `Vendor risk ${num.toFixed(2)}`;
        if (num < 0.50) {
          reason = `Upstream vendor risk score (${num.toFixed(2)}) is below 0.50, penalizing confidence by ${contribution.toFixed(2)}.`;
        } else if (num > 0.50) {
          reason = `Upstream vendor risk score (${num.toFixed(2)}) exceeds 0.50, boosting confidence by +${contribution.toFixed(2)}.`;
        } else {
          reason = 'Upstream vendor risk is at the 0.50 neutral baseline.';
        }
      } else {
        reason = isPenalty
          ? `Low vendor risk score penalized confidence by ${contribution.toFixed(2)}.`
          : `Vendor risk score contributed +${contribution.toFixed(2)}.`;
      }
      break;
    }

    case 'ioc_density': {
      const count = parseCount(valLower);
      observedText = rawVal || (count != null ? `${count} populated field${count === 1 ? '' : 's'}` : '0 populated fields');
      if (count === 0 || (count == null && isPenalty)) {
        reason = '0 populated entity fields found, penalizing confidence by -0.60 due to insufficient investigative context.';
      } else if (count === 1 || count === 2) {
        reason = `${observedText} provided (1-2 fields is the neutral baseline, 0.00 contribution).`;
      } else if (count != null && count >= 3) {
        reason = `${observedText} populated, providing rich investigative context and a +${contribution.toFixed(2)} boost.`;
      } else {
        reason = isPenalty
          ? `IOC field density penalized confidence by ${contribution.toFixed(2)}.`
          : `IOC field density contributed +${contribution.toFixed(2)}.`;
      }
      break;
    }
    case 'institutional_memory': {
      observedText = rawVal || 'Signature feedback prior';
      if (isPenalty) {
        reason = `Analysts previously marked alerts with this signature as benign/false positive, applying a negative adjustment of ${contribution.toFixed(2)}.`;
      } else if (impact === 'boost') {
        reason = `Analysts previously verified alerts with this signature as true positives, applying a positive nudge of +${contribution.toFixed(2)}.`;
      } else {
        reason = 'No significant analyst bias recorded for this signature.';
      }
      break;
    }

    default: {
      if (isPenalty) {
        reason = `Observed condition "${rawVal || 'negative signal'}" resulted in a penalty of ${contribution.toFixed(2)} (weight: ${factor.weight.toFixed(2)}).`;
      } else if (impact === 'boost') {
        reason = `Observed condition "${rawVal || 'positive signal'}" contributed a boost of +${contribution.toFixed(2)} (weight: ${factor.weight.toFixed(2)}).`;
      } else {
        reason = `Observed condition "${rawVal || 'baseline'}" is at the neutral baseline (0.00 contribution).`;
      }
      break;
    }
  }

  const sign = contribution >= 0 ? '+' : '';
  const contributionText = `${sign}${contribution.toFixed(2)}`;
  const weightText = factor.weight.toFixed(2);

  return {
    meta,
    observedText,
    impact,
    isPenalty,
    reason,
    contributionText,
    weightText,
  };
}
