'use client';

import { useState } from 'react';
import useSWR, { mutate } from 'swr';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { request, authApi } from '@/lib/api';

interface Permission {
  id: string;
  name: string;
  description: string | null;
  category: string | null;
}

interface Role {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  permissions: Permission[];
}

const fetcher = (url: string) => request<any>(url);

const CATEGORY_COLORS: Record<string, string> = {
  cases: 'bg-blue-500/20 text-blue-300',
  alerts: 'bg-red-500/20 text-red-300',
  playbooks: 'bg-purple-500/20 text-purple-300',
  detections: 'bg-orange-500/20 text-orange-300',
  connectors: 'bg-teal-500/20 text-teal-300',
  api_keys: 'bg-yellow-500/20 text-yellow-300',
  audit: 'bg-gray-500/20 text-gray-300',
  compliance: 'bg-green-500/20 text-green-300',
  admin: 'bg-pink-500/20 text-pink-300',
};

function PermissionBadge({ perm }: { perm: Permission }) {
  const cls = CATEGORY_COLORS[perm.category ?? ''] ?? 'bg-gray-500/20 text-gray-300';
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${cls}`} title={perm.description ?? ''}>
      {perm.name}
    </span>
  );
}

function RoleCard({ role, onEdit, onDelete }: { role: Role; onEdit: (r: Role) => void; onDelete: (r: Role) => void }) {
  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/60 p-5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-semibold text-gray-100">{role.name}</span>
            {role.is_system && (
              <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-indigo-700">
                system
              </span>
            )}
          </div>
          {role.description && <p className="mt-0.5 text-sm text-gray-400">{role.description}</p>}
        </div>
        <div className="flex shrink-0 gap-2">
          <button
            onClick={() => onEdit(role)}
            className="rounded px-2.5 py-1 text-xs font-medium text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
          >
            수정
          </button>
          {!role.is_system && (
            <button
              onClick={() => onDelete(role)}
              className="rounded px-2.5 py-1 text-xs font-medium text-red-400 hover:bg-red-900/30 transition-colors"
            >
              삭제
            </button>
          )}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {role.permissions.length === 0 ? (
          <span className="text-xs text-gray-600 italic">No permissions assigned</span>
        ) : (
          role.permissions.map((p) => <PermissionBadge key={p.id} perm={p} />)
        )}
      </div>
    </div>
  );
}

interface RoleFormProps {
  allPermissions: Permission[];
  initial?: Role;
  onClose: () => void;
}

function RoleForm({ allPermissions, initial, onClose }: RoleFormProps) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => {
    if (initial?.permissions) {
      return new Set(initial.permissions.map((p) => p.id));
    }
    // New role: default check essential read permissions (:read)
    const defaults = allPermissions
      .filter((p) => p.name.endsWith(':read'))
      .map((p) => p.id);
    return new Set(defaults);
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const categories = Array.from(new Set(allPermissions.map((p) => p.category ?? 'other'))).sort();

  const toggle = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const save = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    setSaving(true);
    setError(null);
    try {
      const url = initial ? `/api/v1/rbac/roles/${initial.id}` : '/api/v1/rbac/roles';
      const method = initial ? 'PATCH' : 'POST';
      await request(url, {
        method,
        body: JSON.stringify({ name: name.trim(), description: description || null, permission_ids: Array.from(selectedIds) }),
      });
      await mutate('/api/v1/rbac/roles');
      onClose();
    } catch (e: any) {
      let msg = e?.message || 'Save failed';
      if (e?.body) {
        try {
          const parsed = JSON.parse(e.body);
          if (parsed.detail) msg = parsed.detail;
        } catch {
          /* not json */
        }
      }
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-2xl rounded-2xl bg-white shadow-2xl">
        <div className="flex items-center justify-between border-b px-6 py-4">
          <h2 className="text-lg font-semibold">{initial ? 'Edit Role' : 'Create Role'}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-700">✕</button>
        </div>
        <div className="space-y-4 px-6 py-4">
          {error && <p className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Role Name</label>
            <input
              value={name}
              disabled={initial?.is_system}
              readOnly={initial?.is_system}
              onChange={(e) => setName(e.target.value)}
              className={`w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 ${initial?.is_system ? 'bg-gray-100 text-gray-500 cursor-not-allowed' : ''}`}
              placeholder="e.g. threat-hunter"
            />
            {initial?.is_system && (
              <p className="mt-1 text-xs text-gray-500">
                시스템 기본 역할 이름은 변경할 수 없으며, 아래 설명 및 세부 권한을 수정할 수 있습니다.
              </p>
            )}
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Description</label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              placeholder="Optional description"
            />
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-gray-700">
              Permissions ({selectedIds.size} selected)
            </label>
            <div className="max-h-64 overflow-y-auto space-y-3 rounded-lg border p-3">
              {categories.map((cat) => (
                <div key={cat}>
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">{cat}</p>
                  <div className="flex flex-wrap gap-2">
                    {allPermissions
                      .filter((p) => (p.category ?? 'other') === cat)
                      .map((perm) => (
                        <label key={perm.id} className="flex cursor-pointer items-center gap-1.5">
                          <input
                            type="checkbox"
                            checked={selectedIds.has(perm.id)}
                            onChange={() => toggle(perm.id)}
                            className="rounded border-gray-300 text-indigo-600"
                          />
                          <span className="text-xs text-gray-700">{perm.name}</span>
                        </label>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 border-t px-6 py-4">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-600 hover:bg-gray-100">
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            {saving ? 'Saving…' : initial ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function RBACView() {
  const currentUser = authApi.currentUser();
  const canWriteRoles = currentUser?.role === 'admin' || currentUser?.role === 'platform_admin' || currentUser?.role === 'tenant_admin' || currentUser?.role === 'soc_lead';

  const { data: roles, error: rolesError } = useSWR<Role[]>('/api/v1/rbac/roles', fetcher, {
    fallbackData: undefined,
  });
  const { data: permissions } = useSWR<Permission[]>('/api/v1/rbac/permissions', fetcher, {
    fallbackData: undefined,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);

  const handleDelete = async (role: Role) => {
    if (!confirm(`Delete role "${role.name}"?`)) return;
    try {
      await request(`/api/v1/rbac/roles/${role.id}`, { method: 'DELETE' });
      mutate('/api/v1/rbac/roles');
    } catch (e: any) {
      alert(e?.message || 'Delete failed');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-100">Roles & Permissions</h2>
          <p className="mt-0.5 text-sm text-gray-500">Manage access control for your organization.</p>
        </div>
        {canWriteRoles && (
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
          >
            + New Role
          </button>
        )}
      </div>

      {rolesError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
          RBAC API unreachable
        </div>
      )}

      {!roles && !rolesError && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-32 animate-pulse rounded-xl bg-gray-800/60" />
          ))}
        </div>
      )}

      {roles && roles.length === 0 && (
        <EmptyState
          icon={EmptyStateIcons.shield}
          title="No roles defined yet"
          description="Create your first role to start managing access control for your organization."
          action={
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 transition-colors"
            >
              + New Role
            </button>
          }
        />
      )}

      {roles && roles.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {roles.map((role) => (
            <RoleCard
              key={role.id}
              role={role}
              onEdit={(r) => setEditingRole(r)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {(showCreate || editingRole) && permissions && (
        <RoleForm
          allPermissions={permissions}
          initial={editingRole ?? undefined}
          onClose={() => {
            setShowCreate(false);
            setEditingRole(null);
          }}
        />
      )}
    </div>
  );
}
