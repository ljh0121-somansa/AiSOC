import type { Alert } from '@/lib/api';

export const normalAlert: Alert = {
  id: 'alert-normal-1',
  title: 'Suspicious Execution',
  description: 'Suspicious process execution detected.',
  severity: 'high',
  status: 'new',
  source: 'edr',
  tenantId: 'tenant-1',
  riskScore: 85,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: {
    user: { name: 'alice' },
    host: { name: 'workstation-01', ip: '192.168.1.50' },
    process: {
      name: 'cmd.exe',
      command_line: 'cmd.exe /c powershell.exe -enc ...',
      parent: { name: 'explorer.exe' },
    },
    file: {
      path: 'C:\\Windows\\System32\\cmd.exe',
      hash: { sha256: 'abc123hash' },
    },
  },
};

export const partialMissingAlert: Alert = {
  id: 'alert-partial-2',
  title: 'Alert without user and process',
  description: 'Network anomaly detected.',
  severity: 'medium',
  status: 'new',
  source: 'network',
  tenantId: 'tenant-1',
  riskScore: 50,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: {
    host: { name: 'server-02', ip: '10.0.0.5' },
  },
};

export const edgeCaseAntiFalsePositiveAlert: Alert = {
  id: 'alert-edge-3',
  title: 'Edge Case Anti False Positive',
  description: 'Testing defang and anti-false positive boundaries.',
  severity: 'critical',
  status: 'new',
  source: 'edr',
  tenantId: 'tenant-1',
  riskScore: 95,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: {
    host: { name: 'host-03', ip: '192.168.1.100' },
    process: {
      name: 'powershell.exe',
      command_line: 'powershell.exe -Command "[Convert]::FromBase64String(\'abc\')" payload.exe 00:1A:2B:3C:4D:5E 12:30:45 1.2.3.4 172.16.0.1 172.32.0.1 2001:db8::1 http://evil.com/payload.exe ' + 'a'.repeat(1200),
      parent: { name: 'cmd.exe' },
    },
  },
};

export const nonProcessAlertA: Alert = {
  id: 'alert-nonproc-4a',
  title: 'Non-process Action Alert',
  description: 'Network traffic anomaly.',
  severity: 'low',
  status: 'new',
  source: 'firewall',
  tenantId: 'tenant-1',
  riskScore: 20,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: {
    event: { action: 'connect' },
    source: { ip: '192.168.1.10' },
    destination: { ip: '8.8.8.8', domain: 'malicious.com' },
    user: { name: 'bob' },
  },
};

export const nonProcessAlertB: Alert = {
  id: 'alert-nonproc-4b',
  title: 'Non-process File Alert',
  description: 'Dropped file detection.',
  severity: 'medium',
  status: 'new',
  source: 'av',
  tenantId: 'tenant-1',
  riskScore: 60,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: {
    file: {
      path: '/tmp/dropped.bin',
      hash: { sha256: 'deadbeefhash' },
    },
  },
};

export const nonProcessAlertC: Alert = {
  id: 'alert-nonproc-4c',
  title: 'Empty RawEvent Alert',
  description: 'No details.',
  severity: 'info',
  status: 'new',
  source: 'system',
  tenantId: 'tenant-1',
  riskScore: 10,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: null as unknown as Record<string, unknown>,
};

export const isolatedDescriptionAlert: Alert = {
  id: 'alert-isolated-5',
  title: 'Isolated JSON Description',
  description: '{"nested": "json description payload that exceeds normal text limits and should be isolated into raw data"}',
  severity: 'high',
  status: 'new',
  source: 'edr',
  tenantId: 'tenant-1',
  riskScore: 80,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: { host: { name: 'host-05' } },
};

export const brokenInputAlert: Alert = {
  id: 'alert-broken-6',
  title: 'Broken Input Alert',
  description: 'Malformed raw event test',
  severity: 'medium',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 40,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  rawEvent: 'invalid string raw event' as unknown as Record<string, unknown>,
};

export const manyIocsAlert: Alert = {
  id: 'alert-iocs-7',
  title: 'Many IOCs Alert',
  description: 'Alert with 51 IOCs',
  severity: 'high',
  status: 'new',
  source: 'intel',
  tenantId: 'tenant-1',
  riskScore: 90,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  iocs: Array.from({ length: 51 }, (_, i) => ({
    type: i % 2 === 0 ? 'ip' : i % 3 === 0 ? 'domain' : 'unknown_type',
    value: i % 2 === 0 ? (i < 5 ? '192.168.1.1' : `8.8.8.${i}`) : `domain-${i}.com`,
    malicious: i % 5 === 0,
  })),
};

export const confidenceScoreAlert1: Alert = {
  id: 'alert-conf-1',
  title: 'Confidence Score 1',
  description: 'Score 1 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: 1,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlert05: Alert = {
  id: 'alert-conf-05',
  title: 'Confidence Score 0.5',
  description: 'Score 0.5 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: 0.5,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlert87: Alert = {
  id: 'alert-conf-87',
  title: 'Confidence Score 87',
  description: 'Score 87 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: 87,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlert875: Alert = {
  id: 'alert-conf-875',
  title: 'Confidence Score 87.5',
  description: 'Score 87.5 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: 87.5,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlert101: Alert = {
  id: 'alert-conf-101',
  title: 'Confidence Score 101',
  description: 'Score 101 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: 101,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlertNegative: Alert = {
  id: 'alert-conf-neg',
  title: 'Confidence Score Negative',
  description: 'Score -1 test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: -1,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlertString: Alert = {
  id: 'alert-conf-str',
  title: 'Confidence Score String',
  description: 'Score "87" test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  confidenceScore: '87' as unknown as number,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const confidenceScoreAlertMissing: Alert = {
  id: 'alert-conf-missing',
  title: 'Confidence Score Missing',
  description: 'Missing score test',
  severity: 'low',
  status: 'new',
  source: 'test',
  tenantId: 'tenant-1',
  riskScore: 30,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const aiSummaryInjectionAlert: Alert = {
  id: 'alert-ai-inj-9',
  title: 'AI Summary Injection',
  description: 'Normal description',
  severity: 'high',
  status: 'new',
  source: 'ai',
  tenantId: 'tenant-1',
  riskScore: 85,
  aiSummary: '<script>alert(1)</script> **Bold Markdown** AI Summary content',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};
