import React from 'react';
import type { Alert, AlertIOC } from '@/lib/api';
import {
  summarizeAlert,
  getJudgmentMeta,
  getResponseStatus,
  getImpactedAsset,
  getDetectionBasis,
  getIocGroup,
  getRecommendedActions,
  serializeRawData,
  getRawDataBadge,
} from '@/lib/alertView';
import { ParentProcessRow } from '@/components/alerts/ParentProcessRow';
import type { ParentProcessStatus } from '@/lib/alertView';

export interface SummaryInfo {
  text: string;
  label?: string;
  isAi: boolean;
}

export interface MitreAttackInfo {
  tags: string[];
  overflowCount: number;
  badge?: string;
}

export interface JudgmentMetaInfo {
  severity: string;
  confidenceScore: number | string;
  sourceKind: string;
  mitreAttack: MitreAttackInfo;
}

export interface ResponseStatusInfo {
  label: string;
  description: string;
  tone: string;
}

export interface ImpactedAssetInfo {
  actor: string;
  hostname: string;
  ip: string;
}

export interface DetectionField {
  label: string;
  value: string;
  rawValue: string;
}

export interface DetectionBasisInfo {
  message?: string;
  name?: string;
  commandLine?: string;
  rawCommandLine?: string;
  filePath?: string;
  fileHash?: string;
  fields?: DetectionField[];
}

export interface IocItem {
  value: string;
  defangedValue: string;
  rawValue: string;
  malicious?: boolean;
}

export interface IocGroupInfo {
  groups?: Record<string, IocItem[]>;
  totalCount?: number;
  displayedCount?: number;
  moreLabel?: string;
  warning?: string;
  reputationStatus: string;
  historyStatus: string;
  message?: string;
}

export interface RecommendedActionItem {
  action: string;
  priority?: string;
  description?: string;
}

export interface SummarySectionProps {
  alert?: Alert;
  summary?: SummaryInfo;
}

export function SummarySection({ alert, summary }: SummarySectionProps): React.ReactNode {
  const resolved = summary || (alert ? summarizeAlert(alert) : { text: 'EDR 탐지 경보', isAi: false });
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 break-words">
      <div className="flex items-center gap-2">
        {resolved.label && (
          <span className="px-2 py-0.5 text-xs bg-blue-500/10 text-blue-400 ring-1 ring-inset ring-blue-500/20 rounded font-medium">
            {resolved.label}
          </span>
        )}
        <span className="text-gray-200 font-medium">{resolved.text}</span>
      </div>
    </div>
  );
}

export interface JudgmentMetaSectionProps {
  alert?: Alert;
  meta?: JudgmentMetaInfo;
}

export function JudgmentMetaSection({ alert, meta }: JudgmentMetaSectionProps): React.ReactNode {
  const resolvedMeta = (meta || (alert ? getJudgmentMeta(alert) : {
    severity: '미확인',
    confidenceScore: '—',
    sourceKind: '미확인',
    mitreAttack: { tags: [], overflowCount: 0 },
  })) as unknown as JudgmentMetaInfo;

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 break-words space-y-3">
      <div className="flex flex-wrap gap-4 items-center text-sm text-gray-300">
        <div>
          <span className="font-semibold text-gray-400">심각도: </span>
          <span className="uppercase text-gray-200">{resolvedMeta.severity}</span>
        </div>
        <div>
          <span className="font-semibold text-gray-400">신뢰도: </span>
          <span className="text-gray-200">{resolvedMeta.confidenceScore}</span>
        </div>
        <div>
          <span className="font-semibold text-gray-400">소스 종류: </span>
          <span className="text-gray-200">{resolvedMeta.sourceKind}</span>
        </div>
        {resolvedMeta.mitreAttack?.tags && resolvedMeta.mitreAttack.tags.length > 0 && (
          <div className="flex items-center gap-1">
            <span className="font-semibold text-gray-400">MITRE: </span>
            {resolvedMeta.mitreAttack.tags.map((tag, idx) => (
              <span key={idx} className="px-1.5 py-0.5 bg-gray-800 text-gray-300 text-xs rounded border border-gray-700">{tag}</span>
            ))}
            {resolvedMeta.mitreAttack.badge && (
              <span className="px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs rounded">{resolvedMeta.mitreAttack.badge}</span>
            )}
          </div>
        )}
      </div>
      <ResponseStatusRow />
    </div>
  );
}

export function ResponseStatusRow(): React.ReactNode {
  const status = getResponseStatus() as unknown as ResponseStatusInfo;
  return (
    <div className="flex items-center justify-between p-2.5 bg-gray-800/60 border border-gray-700/60 rounded-lg text-xs text-gray-300 break-words">
      <div className="flex items-center gap-2">
        <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded font-medium">{status.label}</span>
        <span>{status.description}</span>
      </div>
    </div>
  );
}

export interface ImpactedAssetSectionProps {
  alert?: Alert;
  asset?: ImpactedAssetInfo;
}

export function ImpactedAssetSection({ alert, asset }: ImpactedAssetSectionProps): React.ReactNode {
  const resolvedAsset = (asset || (alert ? getImpactedAsset(alert) : {
    actor: '미확인',
    hostname: '미확인',
    ip: '미확인',
  })) as unknown as ImpactedAssetInfo;

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 break-words space-y-2 text-sm">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">영향 자산</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-gray-300">
        <div><span className="text-gray-500 font-medium">사용자/Actor:</span> <span className="text-gray-200">{resolvedAsset.actor}</span></div>
        <div><span className="text-gray-500 font-medium">호스트:</span> <span className="text-gray-200">{resolvedAsset.hostname}</span></div>
        <div><span className="text-gray-500 font-medium">IP:</span> <span className="text-gray-200">{resolvedAsset.ip}</span></div>
      </div>
    </div>
  );
}

/**
 * On-Demand Parent Process Lazy Loading: the static `parent` field was
 * removed from `getDetectionBasis` (rawEvent OCSF payloads carry only a
 * parent `entity_id`, never `parent.name`). The parent-process line in the
 * detection-basis section now renders the lazy-lookup row, which fires
 * `GET /api/v1/alerts/{id}/parent-process` once per alert view (spec §2
 * Option C: one lookup per viewed alert).
 */
export interface DetectionBasisSectionProps {
  alert?: Alert;
  basis?: DetectionBasisInfo;
  /** Alert id for the lazy parent-process lookup (ParentProcessRow). */
  alertId?: string;
  /** Pre-mapped status; `loading`/absent triggers the on-demand fetch. */
  parentProcess?: ParentProcessStatus | null;
}

export function DetectionBasisSection({ alert, basis, alertId, parentProcess }: DetectionBasisSectionProps): React.ReactNode {
  const [isOpen, setIsOpen] = React.useState(true);
  const [copyStatus, setCopyStatus] = React.useState<string | null>(null);

  const resolvedBasis = (basis || (alert ? getDetectionBasis(alert) : { message: '표시할 탐지 근거 없음 (Raw Data 확인)' })) as unknown as DetectionBasisInfo;

  const lookupAlertId = alertId ?? alert?.id;

  const handleCopy = async (text: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopyStatus('복사됨');
      } else {
        setCopyStatus('복사 실패');
      }
    } catch {
      setCopyStatus('복사 실패');
    }
    setTimeout(() => setCopyStatus(null), 2000);
  };

  return (
    <div className="border border-gray-800/60 rounded-xl bg-gray-900/60 shadow-sm overflow-hidden">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-5 text-left font-semibold text-gray-200 bg-gray-900/80 hover:bg-gray-800/80 transition-colors"
      >
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">탐지 근거</span>
        <span className="text-xs text-gray-500">{isOpen ? '접기' : '펼치기'}</span>
      </button>
      {isOpen && (
        <div className="p-5 space-y-3 text-sm break-words text-gray-200 border-t border-gray-800/60">
          {resolvedBasis.message ? (
            <p className="text-gray-400">{resolvedBasis.message}</p>
          ) : resolvedBasis.name ? (
            <div className="space-y-2">
              <div><span className="font-medium text-gray-400">프로세스:</span> <span className="text-gray-200">{resolvedBasis.name}</span></div>
              {lookupAlertId && (
                <ParentProcessRow alertId={lookupAlertId} status={parentProcess} />
              )}
              {resolvedBasis.commandLine && (
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-gray-400">명령줄:</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(resolvedBasis.rawCommandLine || resolvedBasis.commandLine || '')}
                      className="px-2 py-0.5 text-xs bg-gray-800 hover:bg-gray-700 rounded text-gray-300 border border-gray-700"
                    >
                      {copyStatus || '복사'}
                    </button>
                  </div>
                  <pre className="p-3 bg-gray-950 text-gray-200 rounded text-xs overflow-x-auto font-mono border border-gray-800">{resolvedBasis.commandLine}</pre>
                </div>
              )}
              {resolvedBasis.filePath && (
                <div><span className="font-medium text-gray-400">파일 경로:</span> <span className="text-gray-200">{resolvedBasis.filePath}</span></div>
              )}
              {resolvedBasis.fileHash && (
                <div><span className="font-medium text-gray-400">파일 해시 (SHA256):</span> <code className="text-gray-200 break-all">{resolvedBasis.fileHash}</code></div>
              )}
            </div>
          ) : resolvedBasis.fields && Array.isArray(resolvedBasis.fields) ? (
            <div className="space-y-2">
              {resolvedBasis.fields.map((f: DetectionField, idx: number) => (
                <div key={idx} className="flex flex-col sm:flex-row sm:justify-between border-b border-gray-800/60 pb-1">
                  <span className="font-medium text-gray-400">{f.label}:</span>
                  <span className="font-mono text-gray-200 overflow-x-auto">{f.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-400">탐지 근거 정보 없음</p>
          )}
        </div>
      )}
    </div>
  );
}

export interface ContextSummarySectionProps {
  iocs?: AlertIOC[];
  contextGroup?: IocGroupInfo;
  alert?: Alert;
}

export function ContextSummarySection({ iocs, contextGroup, alert }: ContextSummarySectionProps): React.ReactNode {
  const [isOpen, setIsOpen] = React.useState(false);
  const [copyStatusMap, setCopyStatusMap] = React.useState<Record<string, string>>({});

  const resolvedGroup = (contextGroup || getIocGroup(iocs || alert?.iocs)) as unknown as IocGroupInfo;

  const handleCopy = async (val: string, key: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(val);
        setCopyStatusMap((prev) => ({ ...prev, [key]: '복사됨' }));
      } else {
        setCopyStatusMap((prev) => ({ ...prev, [key]: '복사 실패' }));
      }
    } catch {
      setCopyStatusMap((prev) => ({ ...prev, [key]: '복사 실패' }));
    }
    setTimeout(() => {
      setCopyStatusMap((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    }, 2000);
  };

  return (
    <div className="border border-gray-800/60 rounded-xl bg-gray-900/60 shadow-sm overflow-hidden">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-5 text-left font-semibold text-gray-200 bg-gray-900/80 hover:bg-gray-800/80 transition-colors"
      >
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">컨텍스트 요약 (IOC)</span>
        <span className="text-xs text-gray-500">{isOpen ? '접기' : '펼치기'}</span>
      </button>
      {isOpen && (
        <div className="p-5 space-y-3 text-sm break-words text-gray-200 border-t border-gray-800/60">
          {resolvedGroup.message ? (
            <p className="text-gray-400">{resolvedGroup.message}</p>
          ) : (
            <div className="space-y-3">
              {resolvedGroup.warning && (
                <div className="p-2.5 bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 text-xs rounded-lg">
                  {resolvedGroup.warning}
                </div>
              )}
              <div className="flex gap-4 text-xs text-gray-400">
                <span>평판 평점: <span className="text-gray-200">{resolvedGroup.reputationStatus}</span></span>
                <span>유사 이력: <span className="text-gray-200">{resolvedGroup.historyStatus}</span></span>
              </div>
              {resolvedGroup.groups && Object.entries(resolvedGroup.groups).map(([cat, items]: [string, IocItem[]]) => (
                <div key={cat} className="space-y-1">
                  <h4 className="font-semibold text-gray-400 uppercase text-xs">{cat}</h4>
                  <ul className="space-y-1">
                    {items.map((item: IocItem, idx: number) => {
                      const copyKey = `${cat}-${idx}`;
                      return (
                        <li key={idx} className="flex items-center justify-between p-2 bg-gray-800/60 border border-gray-700/60 rounded-lg text-xs">
                          <code className="font-mono text-gray-200 break-all">{item.value}</code>
                          <button
                            type="button"
                            onClick={() => handleCopy(item.rawValue || item.value, copyKey)}
                            className="ml-2 px-2 py-0.5 bg-gray-700 hover:bg-gray-600 rounded text-gray-200 shrink-0 border border-gray-600"
                          >
                            {copyStatusMap[copyKey] || '복사'}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
              {resolvedGroup.moreLabel && (
                <div className="text-xs text-gray-400 italic">{resolvedGroup.moreLabel}</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function RelatedSignalsBadge(): React.ReactNode {
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
      연관 신호: 미연동
    </span>
  );
}

export interface RecommendedActionsSectionProps {
  actions?: RecommendedActionItem[] | null;
  alert?: Alert;
}

export function RecommendedActionsSection({ actions, alert }: RecommendedActionsSectionProps): React.ReactNode {
  const [isOpen, setIsOpen] = React.useState(false);
  const resolvedActions = (actions || (alert ? getRecommendedActions(alert) : null)) as unknown as RecommendedActionItem[] | null;

  if (!resolvedActions || !Array.isArray(resolvedActions) || resolvedActions.length === 0) {
    return null;
  }

  const actionSummary = resolvedActions.map((act: RecommendedActionItem) => act.action).join(', ');

  return (
    <div className="border border-gray-800/60 rounded-xl bg-gray-900/60 shadow-sm overflow-hidden">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-5 text-left font-semibold text-gray-200 bg-gray-900/80 hover:bg-gray-800/80 transition-colors"
      >
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">권장 조치 ({resolvedActions.length}){actionSummary ? `: ${actionSummary}` : ''}</span>
        <span className="text-xs text-gray-500">{isOpen ? '접기' : '펼치기'}</span>
      </button>
      {isOpen && (
        <div className="p-5 space-y-2 text-sm break-words text-gray-200 border-t border-gray-800/60">
          <ul className="space-y-2">
            {resolvedActions.map((act: RecommendedActionItem, idx: number) => (
              <li key={idx} className="p-2.5 bg-gray-800/60 border border-gray-700/60 rounded-lg text-xs space-y-1">
                <div className="font-semibold text-gray-200">{act.action} {act.priority ? `(우선순위: ${act.priority})` : ''}</div>
                {act.description && <div className="text-gray-400">{act.description}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export interface RawDataSectionProps {
  rawEvent?: unknown;
  description?: string;
  alert?: Alert;
}

export function RawDataSection({ rawEvent, description, alert }: RawDataSectionProps): React.ReactNode {
  const [isOpen, setIsOpen] = React.useState(false);

  const resolvedRawEvent = rawEvent !== undefined ? rawEvent : alert?.rawEvent;
  const resolvedDesc = description !== undefined ? description : (alert?.description || (resolvedRawEvent ? '[원본 Description]' : undefined));
  const baseBadge = getRawDataBadge(resolvedRawEvent, resolvedDesc);
  const badge = `${baseBadge}${resolvedDesc ? ' [원본 Description]' : ''}`;

  return (
    <div className="border border-gray-800/60 rounded-xl bg-gray-900/60 shadow-sm overflow-hidden">
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-5 text-left font-semibold text-gray-200 bg-gray-900/80 hover:bg-gray-800/80 transition-colors"
      >
        <span className="flex items-center gap-2">
          <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Raw Data</span>
          <span className="px-2 py-0.5 text-xs bg-gray-800 text-gray-300 rounded border border-gray-700">{badge}</span>
        </span>
        <span className="text-xs text-gray-500">{isOpen ? '접기' : '펼치기'}</span>
      </button>
      {isOpen && (
        <div className="p-5 space-y-2 text-sm break-words text-gray-200 border-t border-gray-800/60">
          <pre className="p-3 bg-gray-950 text-gray-200 rounded-lg text-xs overflow-x-auto font-mono whitespace-pre-wrap border border-gray-800">
            {serializeRawData(resolvedRawEvent, resolvedDesc)}
          </pre>
        </div>
      )}
    </div>
  );
}
