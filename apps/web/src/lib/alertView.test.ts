import { describe, it, expect } from 'bun:test';
import {
  defangUrl,
  defangIpv4,
  defangIpv6,
  defangIoc,
  isInternalOrSpecialIp,
  isolateDescription,
  summarizeAlert,
  getJudgmentMeta,
  getResponseStatus,
  getImpactedAsset,
  getDetectionBasis,
  getIocGroup,
  serializeRawData,
  getRawDataBadge,
  buildAlertView,
  getParentProcessStatus,
} from './alertView';
import {
  normalAlert,
  partialMissingAlert,
  edgeCaseAntiFalsePositiveAlert,
  nonProcessAlertA,
  nonProcessAlertB,
  nonProcessAlertC,
  isolatedDescriptionAlert,
  brokenInputAlert,
  manyIocsAlert,
  confidenceScoreAlert1,
  confidenceScoreAlert05,
  confidenceScoreAlert87,
  confidenceScoreAlert875,
  confidenceScoreAlert101,
  confidenceScoreAlertNegative,
  confidenceScoreAlertString,
  confidenceScoreAlertMissing,
  aiSummaryInjectionAlert,
} from './alertView.fixtures';

describe('[2a] defang and internal IP checks', () => {
  it('defangs URL host while preserving scheme and path', () => {
    const res = defangUrl('http://evil.com/payload.exe');
    expect(res).toBe('hxxp://evil[.]com/payload.exe');
  });

  it('defangs public IPv4', () => {
    expect(defangIpv4('8.8.8.8')).toBe('8[.]8[.]8[.]8');
  });

  it('leaves private IPv4 unchanged', () => {
    expect(defangIpv4('192.168.1.1')).toBe('192.168.1.1');
  });

  it('defangs public IPv6', () => {
    expect(defangIpv6('2001:db8::1')).toBe('2001[:]db8[:]1');
  });

  it('leaves loopback IPv6 unchanged', () => {
    expect(defangIpv6('::1')).toBe('::1');
  });

  it('recognizes 10.0.0.0/8 as internal', () => {
    expect(isInternalOrSpecialIp('10.0.0.1')).toBe(true);
  });

  it('recognizes 172.16.0.0/12 as internal', () => {
    expect(isInternalOrSpecialIp('172.16.0.1')).toBe(true);
  });

  it('recognizes 192.168.0.0/16 as internal', () => {
    expect(isInternalOrSpecialIp('192.168.0.1')).toBe(true);
  });

  it('recognizes 127.0.0.0/8 as internal', () => {
    expect(isInternalOrSpecialIp('127.0.0.1')).toBe(true);
  });

  it('recognizes 169.254.0.0/16 as link-local', () => {
    expect(isInternalOrSpecialIp('169.254.1.1')).toBe(true);
  });

  it('recognizes fc00::/7 as ULA', () => {
    expect(isInternalOrSpecialIp('fc00::1')).toBe(true);
  });

  it('recognizes 0.0.0.0/8 as special', () => {
    expect(isInternalOrSpecialIp('0.0.0.0')).toBe(true);
  });

  it('recognizes 100.64.0.0/10 as CGNAT', () => {
    expect(isInternalOrSpecialIp('100.64.0.1')).toBe(true);
  });

  it('recognizes 172.32.0.1 as public', () => {
    expect(isInternalOrSpecialIp('172.32.0.1')).toBe(false);
  });

  it('recognizes 172.15.0.1 as public', () => {
    expect(isInternalOrSpecialIp('172.15.0.1')).toBe(false);
  });

  it('recognizes 8.8.8.8 as public', () => {
    expect(isInternalOrSpecialIp('8.8.8.8')).toBe(false);
  });

  it('does not defang filename payload.exe', () => {
    expect(defangIoc('filename', 'payload.exe')).toBe('payload.exe');
  });

  it('does not defang powershell call', () => {
    expect(defangIoc('cmd', '[Convert]::FromBase64String')).toBe('[Convert]::FromBase64String');
  });

  it('does not defang MAC address', () => {
    expect(defangIoc('mac', '00:1A:2B:3C:4D:5E')).toBe('00:1A:2B:3C:4D:5E');
  });

  it('does not defang timestamp', () => {
    expect(defangIoc('time', '12:30:45')).toBe('12:30:45');
  });

  it('does not defang version number', () => {
    expect(defangIoc('version', '1.2.3.4')).toBe('1.2.3.4');
  });
});

describe('[2b] description isolation and summary logic', () => {
  it('isolates JSON starting with {', () => {
    const res = isolateDescription('{"foo": "bar"}');
    expect(res.isolated).toBe(true);
  });

  it('isolates JSON starting with [', () => {
    const res = isolateDescription('[{"foo": "bar"}]');
    expect(res.isolated).toBe(true);
  });

  it('isolates description exceeding 200 chars', () => {
    const res = isolateDescription('a'.repeat(201));
    expect(res.isolated).toBe(true);
  });

  it('keeps short plain text descriptions', () => {
    const res = isolateDescription('Short description alert.');
    expect(res.isolated).toBe(false);
    expect(res.cleanDescription).toBe('Short description alert.');
  });

  it('prioritizes aiSummary with AI label', () => {
    const summary = summarizeAlert(aiSummaryInjectionAlert);
    expect(summary.label).toBe('AI 생성');
    expect(summary.isAi).toBe(true);
  });

  it('combines host and rule.name when aiSummary is absent', () => {
    const summary = summarizeAlert(normalAlert);
    expect(summary.text).toContain('workstation-01');
  });

  it('falls back to default text when no fields match', () => {
    const summary = summarizeAlert(nonProcessAlertC);
    expect(summary.text).toBe('EDR 탐지 경보');
  });
});

describe('[2c] judgment meta and response status', () => {
  it('normalizes unknown severity to 미확인', () => {
    const meta: any = getJudgmentMeta({ ...normalAlert, severity: 'unknown_sev' as any });
    expect(meta.severity).toBe('미확인');
  });

  it('handles confidenceScore 1', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlert1);
    expect(meta.confidenceScore).toBe(100);
  });

  it('handles confidenceScore 0.5', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlert05);
    expect(meta.confidenceScore).toBe(50);
  });

  it('handles confidenceScore 87', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlert87);
    expect(meta.confidenceScore).toBe(87);
  });

  it('handles confidenceScore 87.5 rounding', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlert875);
    expect(meta.confidenceScore).toBe(88);
  });

  it('handles confidenceScore 101 out of range as [—]', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlert101);
    expect(meta.confidenceScore).toBe('[—]');
  });

  it('handles confidenceScore -1 out of range as [—]', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlertNegative);
    expect(meta.confidenceScore).toBe('[—]');
  });

  it('handles string confidenceScore "87"', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlertString);
    expect(meta.confidenceScore).toBe(87);
  });

  it('handles missing confidenceScore as [—]', () => {
    const meta: any = getJudgmentMeta(confidenceScoreAlertMissing);
    expect(meta.confidenceScore).toBe('[—]');
  });

  it('returns 조치 정보 미연동 for response status', () => {
    const status: any = getResponseStatus();
    expect(status.label).toBe('조치 정보 미연동');
  });
});

describe('[2d] impacted asset and detection basis', () => {
  it('extracts impacted asset prioritizing actor', () => {
    const asset: any = getImpactedAsset(normalAlert);
    expect(asset.actor).toBe('alice');
  });

  it('handles detection basis for process with parent chain and cmdline', () => {
    const basis: any = getDetectionBasis(normalAlert);
    expect(basis.commandLine).toContain('[1024]');
  });

  it('handles detection basis for non-process alert a', () => {
    const basis: any = getDetectionBasis(nonProcessAlertA);
    expect(basis).toBeDefined();
  });

  it('handles detection basis for non-process alert b', () => {
    const basis: any = getDetectionBasis(nonProcessAlertB);
    expect(basis).toBeDefined();
  });

  it('handles detection basis for non-process alert c', () => {
    const basis: any = getDetectionBasis(nonProcessAlertC);
    expect(basis).toBeDefined();
  });

  it('handles edge case anti false positive alert detection basis', () => {
    const basis: any = getDetectionBasis(edgeCaseAntiFalsePositiveAlert);
    expect(basis).toBeDefined();
  });
});

describe('[2e] ioc grouping, serialization, size badge and buildAlertView', () => {
  it('groups IOCs up to 50 cap with [50건] warning and unknown type as 기타', () => {
    const group: any = getIocGroup(manyIocsAlert.iocs);
    expect(group.warning).toContain('[50건]');
  });

  it('computes raw data size badge correctly for string', () => {
    expect(getRawDataBadge('test')).toContain('4자');
  });

  it('computes raw data size badge correctly for object', () => {
    expect(getRawDataBadge({ a: 1 })).toContain('키 1개');
  });

  it('computes raw data size badge correctly for array', () => {
    expect(getRawDataBadge([1, 2])).toContain('2개 항목');
  });

  it('computes raw data size badge correctly for missing with description as [원본 Description]', () => {
    expect(getRawDataBadge(undefined, 'desc')).toContain('[원본 Description]');
  });

  it('safely serializes raw data with [[Circular]] reference handling', () => {
    const obj: any = { a: 1 };
    obj.self = obj;
    const serialized = serializeRawData(obj);
    expect(serialized).toContain('[[Circular]]');
  });

  it('handles serialization failure with [직직렬화 실패] message', () => {
    const serialized = serializeRawData(Symbol('invalid'));
    expect(serialized).toContain('[직직렬화 실패]');
  });

  it('builds complete alert view model', () => {
    const view = buildAlertView(normalAlert);
    expect(view).toBeDefined();
  });

  it('handles broken input alert safely with object return', () => {
    const view = buildAlertView(brokenInputAlert);
    expect(view).toBeDefined();
  });
});


describe('[2f] parent process status mapping (getParentProcessStatus)', () => {
  // ─── resolved family: resolved / persisted / edr_lookup all fold to 'resolved' ───

  it('maps "resolved" status to "resolved" and copies allowlisted fields', () => {
    const view = getParentProcessStatus(
      {
        status: 'resolved',
        entity_id: 'parent-uuid-1',
        name: 'explorer.exe',
        pid: 4321,
        executable: 'C:\\Windows\\explorer.exe',
        started_at: '2026-10-22T03:00:10.000Z',
        fetched_at: '2026-10-22T03:12:45.120Z',
        source: 'edr_lookup',
      },
      'eligible',
    );
    expect(view.status).toBe('resolved');
    expect(view.entity_id).toBe('parent-uuid-1');
    expect(view.name).toBe('explorer.exe');
    expect(view.pid).toBe(4321);
    expect(view.executable).toBe('C:\\Windows\\explorer.exe');
    expect(view.started_at).toBe('2026-10-22T03:00:10.000Z');
    expect(view.fetched_at).toBe('2026-10-22T03:12:45.120Z');
    expect(view.source).toBe('edr_lookup');
  });

  it('maps "persisted" status to "resolved"', () => {
    const view = getParentProcessStatus(
      {
        status: 'persisted',
        entity_id: 'parent-uuid-2',
        name: 'cmd.exe',
        pid: 1234,
      },
      'eligible',
    );
    expect(view.status).toBe('resolved');
    expect(view.name).toBe('cmd.exe');
    expect(view.pid).toBe(1234);
  });

  it('maps "edr_lookup" status to "resolved"', () => {
    const view = getParentProcessStatus(
      {
        status: 'edr_lookup',
        entity_id: 'parent-uuid-3',
        name: 'powershell.exe',
        pid: 5678,
      },
      'eligible',
    );
    expect(view.status).toBe('resolved');
    expect(view.name).toBe('powershell.exe');
    expect(view.pid).toBe(5678);
  });

  it('maps parentLookup boolean to parent_lookup field on resolved', () => {
    const view = getParentProcessStatus(
      {
        status: 'resolved',
        entity_id: 'parent-uuid-4',
        name: 'svchost.exe',
        pid: 910,
      },
      true,
    );
    expect(view.parent_lookup).toBe(true);
    expect(view.status).toBe('resolved');
  });

  // ─── passthrough: not_found / unavailable / no_parent / not_applicable ───

  it('passthrough maps "not_found" status to "not_found"', () => {
    const view = getParentProcessStatus(
      {
        status: 'not_found',
        entity_id: 'parent-uuid-5',
      },
      'eligible',
    );
    expect(view.status).toBe('not_found');
    expect(view.entity_id).toBe('parent-uuid-5');
    // No data fields copied for not_found
    expect(view.name).toBeUndefined();
    expect(view.pid).toBeUndefined();
  });

  it('passthrough maps "unavailable" status to "unavailable"', () => {
    const view = getParentProcessStatus(
      {
        status: 'unavailable',
        entity_id: 'parent-uuid-6',
      },
      'eligible',
    );
    expect(view.status).toBe('unavailable');
    expect(view.entity_id).toBe('parent-uuid-6');
  });

  it('passthrough maps "no_parent" status to "no_parent"', () => {
    const view = getParentProcessStatus(
      {
        status: 'no_parent',
      },
      'eligible',
    );
    expect(view.status).toBe('no_parent');
  });

  it('passthrough maps "not_applicable" status to "not_applicable"', () => {
    const view = getParentProcessStatus(
      {
        status: 'not_applicable',
      },
      'eligible',
    );
    expect(view.status).toBe('not_applicable');
  });

  it('passthrough copies entity_id for mapped statuses', () => {
    const view = getParentProcessStatus(
      {
        status: 'not_found',
        entity_id: 'parent-uuid-7',
      },
      'eligible',
    );
    expect(view.entity_id).toBe('parent-uuid-7');
  });

  // ─── snapshot absent: eligibility derived from parentLookup ───

  it('maps "eligible" parentLookup to "loading" when snapshot absent', () => {
    const view = getParentProcessStatus(null, 'eligible');
    expect(view.status).toBe('loading');
    expect(view.parent_lookup).toBe('eligible');
  });

  it('maps "no_parent" parentLookup to "no_parent" when snapshot absent', () => {
    const view = getParentProcessStatus(null, 'no_parent');
    expect(view.status).toBe('no_parent');
    expect(view.parent_lookup).toBe('no_parent');
  });

  it('maps "not_applicable" parentLookup to "not_applicable" when snapshot absent', () => {
    const view = getParentProcessStatus(null, 'not_applicable');
    expect(view.status).toBe('not_applicable');
    expect(view.parent_lookup).toBe('not_applicable');
  });

  it('maps null parentLookup to null status when snapshot absent', () => {
    const view = getParentProcessStatus(null, null);
    expect(view.status).toBe(null);
    expect(view.parent_lookup).toBe(null);
  });

  it('maps undefined parentLookup to null status when snapshot absent', () => {
    const view = getParentProcessStatus(undefined, undefined);
    expect(view.status).toBe(null);
    expect(view.parent_lookup).toBe(null);
  });

  // ─── missing/empty snapshot defaults ───

  it('returns null status when snapshot is null', () => {
    const view = getParentProcessStatus(null, null);
    expect(view.status).toBe(null);
    expect(view.entity_id).toBeUndefined();
    expect(view.name).toBeUndefined();
    expect(view.pid).toBeUndefined();
    expect(view.executable).toBeUndefined();
    expect(view.started_at).toBeUndefined();
    expect(view.fetched_at).toBeUndefined();
    expect(view.source).toBeUndefined();
  });

  it('returns null status when snapshot is undefined', () => {
    const view = getParentProcessStatus(undefined, null);
    expect(view.status).toBe(null);
  });

  it('returns null status when snapshot has no status field', () => {
    const view = getParentProcessStatus(
      {
        entity_id: 'orphan-uuid',
      },
      null,
    );
    expect(view.status).toBe(null);
    expect(view.entity_id).toBeUndefined();
  });

  it('handles empty snapshot object', () => {
    const view = getParentProcessStatus({}, null);
    expect(view.status).toBe(null);
  });

  it('undefined snapshot without parentLookup returns null', () => {
    const view = getParentProcessStatus(undefined, null);
    expect(view.status).toBe(null);
    expect(view.parent_lookup).toBe(null);
  });

  // ─── partial data handling ───

  it('leaves undefined fields as undefined for partial resolved snapshot', () => {
    const view = getParentProcessStatus(
      {
        status: 'resolved',
        entity_id: 'parent-uuid-8',
        name: 'svchost.exe',
      },
      null,
    );
    expect(view.status).toBe('resolved');
    expect(view.entity_id).toBe('parent-uuid-8');
    expect(view.name).toBe('svchost.exe');
    expect(view.pid).toBeUndefined();
    expect(view.executable).toBeUndefined();
    expect(view.started_at).toBeUndefined();
    expect(view.fetched_at).toBeUndefined();
    expect(view.source).toBeUndefined();
  });

  it('handles null values in snapshot fields', () => {
    // The mapper applies ?? undefined, so null inputs become undefined
    // on the UI-facing status — that is the mapped contract.
    const view = getParentProcessStatus(
      {
        status: 'resolved',
        entity_id: 'parent-uuid-9',
        name: null,
        pid: null,
        executable: null,
        started_at: null,
        fetched_at: null,
        source: null,
      },
      null,
    );
    expect(view.status).toBe('resolved');
    expect(view.entity_id).toBe('parent-uuid-9');
    expect(view.name).toBeUndefined();
    expect(view.pid).toBeUndefined();
    expect(view.executable).toBeUndefined();
    expect(view.started_at).toBeUndefined();
    expect(view.fetched_at).toBeUndefined();
    expect(view.source).toBeUndefined();
  });
});
