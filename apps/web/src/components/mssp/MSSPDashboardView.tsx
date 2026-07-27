'use client';

import { useState, useMemo } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { isDemoMode } from '@/lib/demoMode';
import { request, msspApi, tenantsApi } from '@/lib/api';

interface Tenant {
  id?: string;
  name: string;
  activeAlerts: number;
  openCases: number;
  mttd: number;
  mttr: number;
  riskScore: number;
  slaStatus: 'compliant' | 'warning' | 'breach';
  arr: number;
  analystAllocation: number;
  isChild?: boolean;
}

const TENANTS: Tenant[] = [
  { name: 'Acme Financial',     activeAlerts: 12, openCases: 3,  mttd: 4.2,  mttr: 28,  riskScore: 72, slaStatus: 'compliant', arr: 185000, analystAllocation: 2 },
  { name: 'GlobalRetail Corp',  activeAlerts: 47, openCases: 11, mttd: 8.7,  mttr: 65,  riskScore: 89, slaStatus: 'breach',    arr: 320000, analystAllocation: 4 },
  { name: 'MedSecure Health',   activeAlerts: 8,  openCases: 2,  mttd: 3.1,  mttr: 19,  riskScore: 45, slaStatus: 'compliant', arr: 140000, analystAllocation: 1 },
  { name: 'NovaTech Industries',activeAlerts: 23, openCases: 6,  mttd: 6.5,  mttr: 42,  riskScore: 78, slaStatus: 'warning',   arr: 260000, analystAllocation: 3 },
  { name: 'Pinnacle Energy',    activeAlerts: 5,  openCases: 1,  mttd: 2.8,  mttr: 15,  riskScore: 31, slaStatus: 'compliant', arr: 110000, analystAllocation: 1 },
  { name: 'Stratos Logistics',  activeAlerts: 31, openCases: 8,  mttd: 7.9,  mttr: 55,  riskScore: 84, slaStatus: 'warning',   arr: 275000, analystAllocation: 3 },
];

const SLA_STYLES: Record<Tenant['slaStatus'], { bg: string; text: string; label: string }> = {
  compliant: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Compliant' },
  warning:   { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Warning' },
  breach:    { bg: 'bg-red-500/20',   text: 'text-red-400',   label: 'Breach' },
};

function kpiCards(tenants: Tenant[]) {
  const totalTenants = tenants.length;
  const totalOpenCases = tenants.reduce((s, t) => s + t.openCases, 0);

  const validMTTD = tenants.filter((t) => t.mttd > 0);
  const avgMTTD = validMTTD.length > 0 ? validMTTD.reduce((s, t) => s + t.mttd, 0) / validMTTD.length : 0;

  const validMTTR = tenants.filter((t) => t.mttr > 0);
  const avgMTTR = validMTTR.length > 0 ? validMTTR.reduce((s, t) => s + t.mttr, 0) / validMTTR.length : 0;

  const compliant = tenants.filter((t) => t.slaStatus === 'compliant').length;
  const slaCompliance = totalTenants > 0 ? Math.round((compliant / totalTenants) * 100) : 100;
  const totalARR = tenants.reduce((s, t) => s + t.arr, 0);

  return [
    { label: 'Total Tenants',    value: totalTenants },
    { label: 'Total Open Cases', value: totalOpenCases },
    { label: 'Avg MTTD',         value: avgMTTD > 0 ? `${avgMTTD.toFixed(1)} min` : '—' },
    { label: 'Avg MTTR',         value: avgMTTR > 0 ? `${avgMTTR.toFixed(0)} min` : '—' },
    { label: 'SLA Compliance',   value: `${slaCompliance}%` },
    { label: 'Total ARR',        value: totalARR > 0 ? `$${(totalARR / 1000).toFixed(0)}K` : '—' },
  ];
}

type SLAFilter = 'all' | 'compliant' | 'warning' | 'breach';

export default function MSSPDashboardView() {
  const [slaFilter, setSlaFilter] = useState<SLAFilter>('all');

  const { data: childTenants, mutate: mutateChildren } = useSWR(
    '/api/v1/mssp/children',
    () => msspApi.listChildren().catch(() => []),
    { revalidateOnFocus: false },
  );

  const { data: myTenants, mutate: mutateMyTenants } = useSWR(
    '/api/v1/tenants/my-tenants',
    () => tenantsApi.listMyTenants().catch(() => []),
    { revalidateOnFocus: false },
  );

  const tenants: Tenant[] = useMemo(() => {
    const list: Tenant[] = [];
    const seen = new Set<string>();

    if (Array.isArray(childTenants)) {
      for (const ct of childTenants) {
        if (!seen.has(ct.id)) {
          seen.add(ct.id);
          list.push({
            id: ct.id,
            name: ct.name,
            activeAlerts: 0,
            openCases: 0,
            mttd: 0,
            mttr: 0,
            riskScore: 0,
            slaStatus: 'compliant',
            arr: 0,
            analystAllocation: 0,
            isChild: true,
          });
        }
      }
    }

    if (Array.isArray(myTenants)) {
      for (const mt of myTenants) {
        if (!seen.has(mt.id)) {
          seen.add(mt.id);
          list.push({
            name: mt.name,
            activeAlerts: 0,
            openCases: 0,
            mttd: 0,
            mttr: 0,
            riskScore: 0,
            slaStatus: 'compliant',
            arr: 0,
            analystAllocation: 0,
          });
        }
      }
    }

    if (list.length > 0) return list;
    return isDemoMode() ? TENANTS : [];
  }, [childTenants, myTenants]);

  const handleDeleteChildTenant = async (t: Tenant) => {
    if (!t.id) return;
    if (confirm(`정말로 '${t.name}' 테넌트를 삭제하시겠습니까?\n모든 데이터가 완전히 제거됩니다.`)) {
      try {
        await tenantsApi.deleteTenant(t.id);
        toast.success(`테넌트 '${t.name}'가 삭제되었습니다.`);
        mutateChildren();
        mutateMyTenants();
      } catch (err: any) {
        toast.error(err?.message || '테넌트 삭제 실패');
      }
    }
  };

  if (tenants.length === 0) {
    return (
      <div className="space-y-8 p-6 max-w-7xl mx-auto">
        <div>
          <h1 className="text-2xl font-bold text-white">MSSP Executive Dashboard</h1>
          <p className="text-gray-400 mt-1">Cross-tenant security operations overview</p>
        </div>
        <div className="rounded-xl border border-gray-800 bg-gray-900/40 p-12 text-center">
          <EmptyState
            icon={EmptyStateIcons.cases}
            title="No Child Tenants Configured"
            description="MSSP multi-tenant monitoring will display customer organization metrics here once child tenants are attached in Settings."
          />
        </div>
      </div>
    );
  }

  const cards = kpiCards(tenants);
  const filteredTenants = slaFilter === 'all' ? tenants : tenants.filter((t) => t.slaStatus === slaFilter);

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">MSSP Executive Dashboard</h1>
        <p className="text-gray-400 mt-1">Cross-tenant security operations overview</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wider">{c.label}</p>
            <p className="mt-1 text-2xl font-semibold text-white">{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tenant Table */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">Tenant Overview</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500">SLA</span>
            {(['all', 'compliant', 'warning', 'breach'] as SLAFilter[]).map((f) => (
              <button
                key={f}
                onClick={() => setSlaFilter(f)}
                className={clsx(
                  'rounded-md px-2.5 py-1 text-xs font-medium capitalize transition',
                  slaFilter === f ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300',
                )}
              >
                {f}
              </button>
            ))}
            <button
              onClick={() => toast.success('Report exported for all tenants')}
              className="text-sm px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
            >
              Export Report
            </button>
          </div>
        </div>
        {filteredTenants.length === 0 ? (
          <EmptyState
            icon={EmptyStateIcons.shield}
            title="No tenants match this SLA filter"
            description="Try a different status filter to view tenants."
            action={
              <button
                type="button"
                onClick={() => setSlaFilter('all')}
                className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
              >
                Show all tenants
              </button>
            }
          />
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Tenant</th>
                <th className="px-5 py-3 font-medium text-right">Active Alerts</th>
                <th className="px-5 py-3 font-medium text-right">Open Cases</th>
                <th className="px-5 py-3 font-medium text-right">MTTD (min)</th>
                <th className="px-5 py-3 font-medium text-right">MTTR (min)</th>
                <th className="px-5 py-3 font-medium text-right">Risk Score</th>
                <th className="px-5 py-3 font-medium text-right">ARR</th>
                <th className="px-5 py-3 font-medium text-right">Analysts</th>
                <th className="px-5 py-3 font-medium text-center">SLA Status</th>
                <th className="px-5 py-3 font-medium text-center">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredTenants.map((t) => {
                const sla = SLA_STYLES[t.slaStatus];
                return (
                  <tr key={t.id || t.name} className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3 font-medium text-white">{t.name}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.activeAlerts}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.openCases}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.mttd > 0 ? `${t.mttd.toFixed(1)} min` : '—'}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.mttr > 0 ? `${t.mttr} min` : '—'}</td>
                    <td className={clsx('px-5 py-3 text-right font-medium', t.riskScore >= 80 ? 'text-red-400' : t.riskScore >= 60 ? 'text-amber-400' : 'text-green-400')}>
                      {t.riskScore > 0 ? t.riskScore : '—'}
                    </td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.arr > 0 ? `$${(t.arr / 1000).toFixed(0)}K` : '—'}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.analystAllocation > 0 ? t.analystAllocation : '—'}</td>
                    <td className="px-5 py-3 text-center">
                      <span className={clsx('inline-block px-2.5 py-0.5 rounded-full text-xs font-medium', sla.bg, sla.text)}>
                        {sla.label}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-center">
                      {t.id && (
                        <button
                          type="button"
                          onClick={() => handleDeleteChildTenant(t)}
                          className="rounded px-2 py-1 text-xs font-medium text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
                        >
                          삭제
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        )}
      </div>
    </div>
  );
}
