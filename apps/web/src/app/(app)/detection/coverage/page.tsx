import { MitreRuleHeatmap } from '@/components/detections/MitreRuleHeatmap';

export const metadata = {
  title: 'MITRE ATT&CK Coverage',
  description:
    "MITRE ATT&CK coverage matrix derived from AiSOC's shipped detections, broken down by tier (native, imported, community).",
};

export default function CoveragePage() {
  return <MitreRuleHeatmap />
}
