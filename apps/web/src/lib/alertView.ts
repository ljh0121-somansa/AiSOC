import type {
  Alert,
  AlertIOC,
  ParentProcessResponse,
  ParentProcessLookupStatus,
} from '@/lib/api';

export interface ParentProcessStatus {
  status:
    | 'loading'
    | 'resolved'
    | 'not_found'
    | 'unavailable'
    | 'no_parent'
    | 'not_applicable'
    | null;
  entity_id?: string;
  name?: string;
  pid?: number | null;
  executable?: string | null;
  started_at?: string | null;
  source?: string | null;
  fetched_at?: string | null;
  parent_lookup?: ParentProcessLookupStatus | null;
}

export interface AlertViewModel {
  summary: { text: string; label?: string; isAi: boolean };
  judgmentMeta: unknown;
  responseStatus: unknown;
  impactedAsset: unknown;
  detectionBasis: unknown;
  iocGroup: unknown;
  recommendedActions: unknown;
  rawData: unknown;
  parentProcess: ParentProcessStatus;
}

export function buildAlertView(alert: Alert): AlertViewModel {
  const parentLookup = alert?.parentLookup ?? null;
  if (!alert) {
    return {
      summary: { text: 'EDR 탐지 경보', isAi: false },
      judgmentMeta: getJudgmentMeta(alert),
      responseStatus: getResponseStatus(),
      impactedAsset: getImpactedAsset(alert),
      detectionBasis: getDetectionBasis(alert),
      iocGroup: getIocGroup(undefined),
      recommendedActions: null,
      rawData: {
        badge: getRawDataBadge(undefined, undefined),
        cleanDescription: '',
      },
      parentProcess: getParentProcessStatus(null, parentLookup),
    };
  }
  const desc = alert.description;
  const { isolated, cleanDescription } = isolateDescription(desc);
  return {
    summary: summarizeAlert(alert),
    judgmentMeta: getJudgmentMeta(alert),
    responseStatus: getResponseStatus(),
    impactedAsset: getImpactedAsset(alert),
    detectionBasis: getDetectionBasis(alert),
    iocGroup: getIocGroup(alert.iocs),
    recommendedActions: getRecommendedActions(alert),
    rawData: {
      badge: getRawDataBadge(alert.rawEvent, isolated ? desc : undefined),
      cleanDescription: isolated ? undefined : cleanDescription,
    },
    parentProcess: getParentProcessStatus(
      alert.parentProcess,
      alert.parentLookup ?? null,
    ),
  };
}

/**
 * Map the server-supplied parent-process snapshot into the UI-facing
 * `ParentProcessStatus`. The status is the server's classification, so the
 * mapper never re-derives eligibility from `rawEvent` — it simply folds the
 * wire `status` (which may be `resolved`/`persisted`/`edr_lookup`) onto the
 * UI enum, copies the allowlisted fields, and defaults a missing/empty
 * snapshot to `null` ("not yet looked up"). `parentLookup` reports whether
 * the server actually ran the lookup, independent of the outcome.
 */
export function getParentProcessStatus(
  snapshot: ParentProcessResponse | null | undefined,
  parentLookup: ParentProcessLookupStatus | null | undefined,
): ParentProcessStatus {
  const RESOLVED_STATES: Record<string, true> = {
    resolved: true,
    persisted: true,
    'edr_lookup': true,
  };
  if (snapshot && snapshot.status) {
    const snapshotStatus = snapshot.status;
    return {
      status: RESOLVED_STATES[snapshotStatus]
        ? 'resolved'
        : (snapshotStatus as ParentProcessStatus['status']),
      entity_id: snapshot.process_id ?? snapshot.entity_id ?? undefined,
      name: snapshot.name ?? undefined,
      pid: snapshot.pid ?? undefined,
      executable: snapshot.executable ?? undefined,
      started_at: snapshot.started_at ?? undefined,
      source: snapshot.source ?? undefined,
      fetched_at: snapshot.fetched_at ?? undefined,
      parent_lookup: parentLookup ?? null,
    };
  }
  const eligibility = parentLookup ?? null;
  return {
    status: eligibility === 'no_parent'
      ? 'no_parent'
      : eligibility === 'not_applicable'
        ? 'not_applicable'
        : eligibility === 'eligible'
          ? 'loading'
          : null,
    parent_lookup: eligibility,
  };
}

export function defangUrl(url: string): string {
  if (!url || typeof url !== 'string') return url;
  const trimmed = url.trim();
  const match = trimmed.match(/^(https?):\/\//i);
  if (!match) {
    return trimmed;
  }
  const scheme = match[1].toLowerCase();
  const defangedScheme = scheme === 'http' ? 'hxxp' : 'hxxps';
  const rest = trimmed.slice(match[0].length);
  const hostEndMatch = rest.match(/^[^\/?#]+/);
  if (!hostEndMatch) {
    return defangedScheme + '://' + rest;
  }
  const hostPart = hostEndMatch[0];
  const pathPart = rest.slice(hostPart.length);
  const defangedHost = hostPart.replace(/\./g, '[.]');
  return defangedScheme + '://' + defangedHost + pathPart;
}

export function defangIpv4(ip: string): string {
  if (!ip || typeof ip !== 'string') return ip;
  const trimmed = ip.trim();
  const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4Match) return ip;
  const o1 = parseInt(ipv4Match[1], 10);
  const o2 = parseInt(ipv4Match[2], 10);
  const o3 = parseInt(ipv4Match[3], 10);
  const o4 = parseInt(ipv4Match[4], 10);
  if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) return ip;
  if (isInternalOrSpecialIp(trimmed)) {
    return trimmed;
  }
  return trimmed.replace(/\./g, '[.]');
}

export function defangIpv6(ip: string): string {
  if (!ip || typeof ip !== 'string') return ip;
  const trimmed = ip.trim();
  if (/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(trimmed)) return trimmed;
  if (/^\d{2}:\d{2}:\d{2}$/.test(trimmed)) return trimmed;
  if (!/:/.test(trimmed)) return trimmed;
  if (isInternalOrSpecialIp(trimmed)) {
    return trimmed;
  }
  return trimmed.replace(/:+/g, '[:]');
}

export function defangIoc(type: string, value: string): string {
  if (!value || typeof value !== 'string') return value;
  const t = (type || '').toLowerCase();
  const val = value.trim();
  if (t === 'url') {
    return defangUrl(val);
  }
  if (t === 'domain') {
    return val.replace(/\./g, '[.]');
  }
  if (t === 'ipv4' || t === 'ip') {
    return defangIpv4(val);
  }
  if (t === 'ipv6') {
    return defangIpv6(val);
  }
  return val;
}

export function isInternalOrSpecialIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const o1 = parseInt(ipv4Match[1], 10);
    const o2 = parseInt(ipv4Match[2], 10);
    const o3 = parseInt(ipv4Match[3], 10);
    const o4 = parseInt(ipv4Match[4], 10);
    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) return false;
    if (o1 === 0) return true;
    if (o1 === 10) return true;
    if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;
    if (o1 === 127) return true;
    if (o1 === 169 && o2 === 254) return true;
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 === 192 && o2 === 168) return true;
    if (o1 >= 224 && o1 <= 239) return true;
    if (o1 === 255 && o2 === 255 && o3 === 255 && o4 === 255) return true;
    return false;
  }
  const lower = trimmed.toLowerCase();
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  if (lower === '::') return true;
  if (/^fe[89ab][0-9a-f]:/i.test(lower) || /^fe[89ab][0-9a-f]$/i.test(lower)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(lower) || /^f[cd][0-9a-f]{2}$/i.test(lower)) return true;
  if (/^ff[0-9a-f]{2}:/i.test(lower)) return true;
  return false;
}

export function isolateDescription(description: string): { isolated: boolean; cleanDescription: string } {
  if (!description || typeof description !== 'string') {
    return { isolated: false, cleanDescription: '' };
  }
  const trimmed = description.trim();
  const isolated = trimmed.startsWith('{') || trimmed.startsWith('[') || trimmed.length > 200;
  return {
    isolated,
    cleanDescription: isolated ? '' : description,
  };
}

function getEffectiveEvent(raw: Record<string, unknown> | undefined, desc?: string): Record<string, unknown> | undefined {
  if (!raw) {
    if (desc && typeof desc === 'string' && desc.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(desc.trim());
        if (parsed && typeof parsed === 'object') {
          return (parsed.raw_event && typeof parsed.raw_event === 'object' ? parsed.raw_event : parsed) as Record<string, unknown>;
        }
      } catch {}
    }
    return undefined;
  }
  if (raw.process && typeof raw.process === 'object') {
    return raw;
  }
  if (typeof raw.raw_data === 'string' && raw.raw_data.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(raw.raw_data.trim());
      if (parsed && typeof parsed === 'object') {
        return (parsed.raw_event && typeof parsed.raw_event === 'object' ? parsed.raw_event : parsed) as Record<string, unknown>;
      }
    } catch {}
  }
  if (raw.raw_event && typeof raw.raw_event === 'object') {
    return raw.raw_event as Record<string, unknown>;
  }
  if (desc && typeof desc === 'string' && desc.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(desc.trim());
      if (parsed && typeof parsed === 'object') {
        return (parsed.raw_event && typeof parsed.raw_event === 'object' ? parsed.raw_event : parsed) as Record<string, unknown>;
      }
    } catch {}
  }
  return raw;
}

export function summarizeAlert(alert: Alert): { text: string; label?: string; isAi: boolean } {
  if (!alert) {
    return { text: 'EDR 탐지 경보', isAi: false };
  }

  if (alert.aiSummary && typeof alert.aiSummary === 'string' && alert.aiSummary.trim().length > 0) {
    return {
      text: alert.aiSummary,
      label: 'AI 생성',
      isAi: true,
    };
  }

  const raw = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : undefined;
  const effective = getEffectiveEvent(raw, alert.description);

  const rawHost = (raw?.host as Record<string, unknown>)?.name || (raw?.device as Record<string, unknown>)?.name || (effective?.host as Record<string, unknown>)?.name;
  const alertRec = alert as unknown as { hostname?: string };
  const host = typeof rawHost === 'string' ? rawHost : (typeof alertRec.hostname === 'string' ? alertRec.hostname : undefined);
  const rawRule = (raw?.rule as Record<string, unknown>)?.name || (effective?.rule as Record<string, unknown>)?.name;
  const ruleName = typeof rawRule === 'string' ? rawRule : alert.title;

  if (host && ruleName) {
    const rawProcess = (raw?.process as Record<string, unknown>)?.name || (effective?.process as Record<string, unknown>)?.name;
    const processName = typeof rawProcess === 'string' ? rawProcess : undefined;

    let text = '';
    if (processName) {
      text = `${host}에서 ${processName}가 ${ruleName} 규칙에 의해 탐지되었습니다`;
    } else {
      text = `${host}에서 ${ruleName} 규칙에 의해 탐지되었습니다`;
    }
    return { text, isAi: false };
  }

  return { text: 'EDR 탐지 경보', isAi: false };
}

export function getJudgmentMeta(alert: Alert): unknown {
  if (!alert) {
    return {
      severity: '미확인',
      confidenceScore: '—',
      sourceKind: '미확인',
      mitreAttack: { tags: [], overflowCount: 0 },
      responseStatus: getResponseStatus(),
    };
  }

  const validSeverities = ['low', 'medium', 'high', 'critical'];
  const rawSev = typeof alert.severity === 'string' ? alert.severity.toLowerCase() : '';
  const severity = validSeverities.includes(rawSev) ? rawSev : '미확인';

  let confidenceScore: number | string = '[—]';
  const rawScore = alert.confidenceScore;
  if (rawScore !== undefined && rawScore !== null && rawScore !== 0) {
    const num = Number(rawScore);
    if (!isNaN(num) && num >= 0 && num <= 100) {
      if (num <= 1) {
        confidenceScore = Math.round(num * 100);
      } else {
        confidenceScore = Math.round(num);
      }
    }
  }

  const rawEvent = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : undefined;
  const edr = rawEvent && 'edr' in rawEvent && rawEvent.edr && typeof rawEvent.edr === 'object' ? rawEvent.edr : undefined;
  const alertObj = alert as unknown as Record<string, unknown>;
  const rawSourceKind = (edr && 'source_kind' in edr ? edr.source_kind : undefined) ??
    (rawEvent && 'source_kind' in rawEvent ? rawEvent.source_kind : undefined) ??
    ('sourceKind' in alertObj ? alertObj.sourceKind : undefined);

  let sourceKind = '미확인';
  if (rawSourceKind === 'dynamic' || rawSourceKind === 'static') {
    sourceKind = rawSourceKind;
  }

  const mitre = alert.mitreAttack || [];
  const tags = mitre.slice(0, 3);
  const overflow = mitre.length > 3 ? mitre.length - 3 : 0;

  return {
    severity,
    confidenceScore,
    sourceKind,
    mitreAttack: {
      tags,
      overflowCount: overflow,
      badge: overflow > 0 ? `+${overflow}` : undefined,
    },
    responseStatus: getResponseStatus(),
  };
}

export function getResponseStatus(): unknown {
  return {
    label: '조치 정보 미연동',
    description: 'EDR 조치 정보가 연동되지 않았으므로 EDR 콘솔에서 확인 필요',
    tone: 'neutral',
  };
}

export function getImpactedAsset(alert: Alert): unknown {
  if (!alert) {
    return {
      actor: '미확인',
      hostname: '미확인',
      ip: '미확인',
    };
  }
  const raw = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : undefined;
  const effective = getEffectiveEvent(raw, alert.description);

  const rawUser = raw && 'user' in raw && raw.user && typeof raw.user === 'object' && 'name' in raw.user ? (raw.user as Record<string, unknown>).name : undefined;
  const ocsfUser = raw && 'actor' in raw && raw.actor && typeof raw.actor === 'object' && 'user' in raw.actor && raw.actor.user && typeof raw.actor.user === 'object' && 'name' in raw.actor.user ? (raw.actor.user as Record<string, unknown>).name : undefined;
  const effectiveUser = effective && 'user' in effective && effective.user && typeof effective.user === 'object' && 'name' in effective.user ? (effective.user as Record<string, unknown>).name : undefined;

  const rawHost = raw && 'host' in raw && raw.host && typeof raw.host === 'object' && 'name' in raw.host ? (raw.host as Record<string, unknown>).name : undefined;
  const ocsfDevice = raw && 'device' in raw && raw.device && typeof raw.device === 'object' && 'name' in raw.device ? (raw.device as Record<string, unknown>).name : undefined;
  const effectiveHost = effective && 'host' in effective && effective.host && typeof effective.host === 'object' && 'name' in effective.host ? (effective.host as Record<string, unknown>).name : undefined;

  const rawIp = raw && 'host' in raw && raw.host && typeof raw.host === 'object' && 'ip' in raw.host ? (raw.host as Record<string, unknown>).ip : undefined;
  const ocsfIp = raw && 'device' in raw && raw.device && typeof raw.device === 'object' && 'ip' in raw.device ? (raw.device as Record<string, unknown>).ip : undefined;
  const effectiveIp = effective && 'host' in effective && effective.host && typeof effective.host === 'object' && 'ip' in effective.host ? (effective.host as Record<string, unknown>).ip : undefined;

  const alertObj = alert as unknown as Record<string, unknown>;
  const actor = ('actor' in alertObj && typeof alertObj.actor === 'string' ? alertObj.actor : undefined) ||
    (typeof rawUser === 'string' ? rawUser : undefined) ||
    (typeof ocsfUser === 'string' ? ocsfUser : undefined) ||
    (typeof effectiveUser === 'string' ? effectiveUser : undefined) ||
    '미확인';
  const hostname = (typeof rawHost === 'string' ? rawHost : undefined) ||
    (typeof ocsfDevice === 'string' ? ocsfDevice : undefined) ||
    (typeof effectiveHost === 'string' ? effectiveHost : undefined) ||
    ('hostname' in alertObj && typeof alertObj.hostname === 'string' ? alertObj.hostname : undefined) ||
    '미확인';
  const ip = (typeof rawIp === 'string' ? rawIp : undefined) ||
    (typeof ocsfIp === 'string' ? ocsfIp : undefined) ||
    (typeof effectiveIp === 'string' ? effectiveIp : undefined) ||
    ('ip' in alertObj && typeof alertObj.ip === 'string' ? alertObj.ip : undefined) ||
    ('host_ip' in alertObj && typeof alertObj.host_ip === 'string' ? alertObj.host_ip : undefined) ||
    '미확인';

  return {
    actor,
    hostname,
    ip,
  };
}


export function getRecommendedActions(alert: Alert): unknown {
  if (!alert || !alert.recommendedActions || !Array.isArray(alert.recommendedActions) || alert.recommendedActions.length === 0) {
    return null;
  }
  return alert.recommendedActions;
}

function defangCommandLine(cmd: string): string {
  if (!cmd || typeof cmd !== 'string') return cmd;
  let res = cmd.replace(/https?:\/\/[^\s]+/gi, (url) => defangUrl(url));
  res = res.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (match) => {
    return defangIpv4(match);
  });
  res = res.replace(/\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g, (match) => {
    return defangIpv6(match);
  });
  return res;
}

export function getDetectionBasis(alert: Alert): unknown {
  if (!alert || !alert.rawEvent || typeof alert.rawEvent !== 'object') {
    return { message: '표시할 탐지 근거 없음 (Raw Data 확인)' };
  }
  const raw = alert.rawEvent as Record<string, unknown>;
  const effective = getEffectiveEvent(raw, alert.description) || raw;
  const process = (effective.process || raw.process) as Record<string, unknown> | undefined;

  if (process && typeof process.name === 'string' && process.name.trim().length > 0) {
    const rawCmd = typeof process.command_line === 'string' ? process.command_line : (typeof process.commandLine === 'string' ? process.commandLine : '');
    
    let truncated = rawCmd;
    if (rawCmd.length > 1024) {
      truncated = rawCmd.slice(0, 1024) + '... [1024] (전체는 Raw Data에서 확인)';
    } else if (rawCmd.length > 0) {
      truncated = rawCmd + ' [1024]';
    }
    const defangedCmd = defangCommandLine(truncated);

    const file = (effective.file || raw.file) as Record<string, unknown> | undefined;
    const filePath = file && typeof file.path === 'string' ? file.path : undefined;
    const fileHashObj = file && file.hash && typeof file.hash === 'object' ? (file.hash as Record<string, unknown>) : undefined;
    const fileHash = fileHashObj && typeof fileHashObj.sha256 === 'string' ? fileHashObj.sha256 : (file && typeof file.hash === 'string' ? file.hash : undefined);

    return {
      name: process.name,
      commandLine: defangedCmd,
      rawCommandLine: rawCmd,
      filePath,
      fileHash,
    };
  }

  const allowedKeys = [
    { path: ['event', 'action'], type: 'string' },
    { path: ['source', 'ip'], type: 'ip' },
    { path: ['destination', 'ip'], type: 'ip' },
    { path: ['destination', 'domain'], type: 'domain' },
    { path: ['user', 'name'], type: 'string' },
    { path: ['file', 'path'], type: 'string' },
    { path: ['file', 'hash', 'sha256'], type: 'string' },
  ];

  const fields: Array<{ label: string; value: string; rawValue: string }> = [];

  for (const item of allowedKeys) {
    let curr: unknown = effective;
    let found = true;
    for (const key of item.path) {
      if (curr && typeof curr === 'object' && curr !== null && key in curr) {
        curr = (curr as Record<string, unknown>)[key];
      } else {
        found = false;
        break;
      }
    }
    if (!found) {
      curr = raw;
      found = true;
      for (const key of item.path) {
        if (curr && typeof curr === 'object' && curr !== null && key in curr) {
          curr = (curr as Record<string, unknown>)[key];
        } else {
          found = false;
          break;
        }
      }
    }
    if (found && curr !== undefined && curr !== null && curr !== '') {
      const valStr = String(curr);
      let defangedVal = valStr;
      if (item.type === 'ip') {
        defangedVal = defangIpv4(valStr);
        if (defangedVal === valStr) {
          defangedVal = defangIpv6(valStr);
        }
      } else if (item.type === 'domain') {
        defangedVal = defangIoc('domain', valStr);
      }
      fields.push({
        label: item.path.join('.'),
        value: defangedVal,
        rawValue: valStr,
      });
    }
  }

  if (fields.length === 0) {
    return { message: '표시할 탐지 근거 없음 (Raw Data 확인)' };
  }

  return { fields };
}

export function getIocGroup(iocs?: AlertIOC[]): unknown {
  if (!iocs || !Array.isArray(iocs) || iocs.length === 0) {
    return {
      items: [],
      warning: undefined,
      reputationStatus: '미연동',
      historyStatus: '미연동',
      message: '수집된 IOC 및 평판 정보 없음',
    };
  }

  const totalCount = iocs.length;
  const cappedIocs = iocs.slice(0, 50);
  let warning: string | undefined = undefined;
  if (totalCount > 50) {
    warning = `총 ${totalCount}건 중 [50건] 표시`;
  }

  const groups: Record<string, Array<{ value: string; defangedValue: string; rawValue: string; malicious?: boolean }>> = {};

  for (const ioc of cappedIocs) {
    const cat = (!ioc.type || ioc.type === 'unknown_type') ? '기타' : ioc.type;

    if (!groups[cat]) {
      groups[cat] = [];
    }

    const val = typeof ioc.value === 'string' ? ioc.value : '';
    const defanged = defangIoc(ioc.type, val);

    groups[cat].push({
      value: defanged,
      defangedValue: defanged,
      rawValue: val,
      malicious: ioc.malicious,
    });
  }

  const displayCount = Math.min(cappedIocs.length, 20);
  const moreCount = cappedIocs.length > 20 ? cappedIocs.length - 20 : 0;

  return {
    groups,
    totalCount,
    displayedCount: cappedIocs.length,
    defaultDisplayLimit: 20,
    moreCount,
    moreLabel: moreCount > 0 ? `${moreCount}건 더보기` : undefined,
    warning,
    reputationStatus: '미연동',
    historyStatus: '미연동',
  };
}

export function serializeRawData(rawEvent: unknown, description?: string): string {
  try {
    if (typeof rawEvent === 'symbol') {
      return '[직직렬화 실패]';
    }
    if (rawEvent === undefined || rawEvent === null) {
      let res = '없음';
      if (description) {
        res += `\n\n[원본 Description]\n${description}`;
      }
      return res;
    }
    const seen = new WeakSet();
    const json = JSON.stringify(rawEvent, (_key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) {
          return '[[Circular]]';
        }
        seen.add(value);
      }
      if (typeof value === 'symbol' || typeof value === 'function') {
        return String(value);
      }
      return value;
    }, 2);

    let result = json !== undefined ? json : String(rawEvent);
    if (description) {
      result += `\n\n[원본 Description]\n${description}`;
    }
    return result;
  } catch {
    return '[직직렬화 실패]';
  }
}

export function getRawDataBadge(rawEvent: unknown, description?: string): string {
  if (rawEvent === undefined || rawEvent === null) {
    if (description && typeof description === 'string' && description.trim().length > 0) {
      return '[원본 Description]';
    }
    return '없음';
  }
  if (typeof rawEvent === 'string') {
    return `${rawEvent.length}자`;
  }
  if (Array.isArray(rawEvent)) {
    return `${rawEvent.length}개 항목`;
  }
  if (typeof rawEvent === 'object') {
    const keysCount = Object.keys(rawEvent as Record<string, unknown>).length;
    return `키 ${keysCount}개`;
  }
  return '없음';
}
