import { TableDownload } from "./TableDownload";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { json, request, useApi } from "./api";
import type { Me, Workspace } from "./types";
import { Panel, State } from "./ui";

type Role = "read" | "write" | "admin";
type Member = { user_id: string; email: string; role: Role };
type Invitation = Member & { workspace_id: string; name: string };
type People = { members: Member[]; invitations: Member[] };
const roles: Role[] = ["read", "write", "admin"];

export function Workspaces({ me, workspaceId, onWorkspaceCreated }: { me?: Me; workspaceId: string; onWorkspaceCreated: (id: string) => void }) {
  const client = useQueryClient();
  const workspaces = useApi<{ items: Workspace[] }>("/workspaces", false);
  const invitations = useApi<{ items: Invitation[] }>("/workspaces/invitations", false);
  const current = workspaces.data?.items.find((item) => item.id === workspaceId);
  const people = useApi<People>(`/workspaces/${encodeURIComponent(workspaceId)}/people`, false, !!current && !current.personal && current.role === "admin");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("read");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const paid = me?.plan === "paid";
  const ownedCount = workspaces.data?.items.filter((item) => !item.personal && item.owner === me?.tenant_id).length ?? 0;

  async function act(action: () => Promise<unknown>, done?: () => void) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await action();
      done?.();
      await client.invalidateQueries({ queryKey: ["live"] });
      setMessage("Workspace updated.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Workspace update failed");
    } finally {
      setBusy(false);
    }
  }
  return <Panel title="Workspaces" kicker="COLLABORATION" className="workspace-settings">
    {workspaces.isPending ? <State loading /> : workspaces.error ? <State error={workspaces.error} onRetry={() => void workspaces.refetch()} /> : <>
      <div className="table-toolbar">
        <p className="muted small">Personal Workspace is private. Create a named workspace to share connectors and assessments.</p>
        <TableDownload table="workspaces" label="workspace list" rows={(workspaces.data?.items || []).map(item => ({
          id: item.id, name: item.name, role: item.role, private: !!item.personal, selected: item.id === workspaceId,
        }))} />
      </div>
      <div className="workspace-settings-list">
        {workspaces.data?.items.map((item) => <div key={item.id}><strong>{item.name}</strong><span>{item.role === "admin" ? "Admin" : item.role === "write" ? "Write" : "Read"}{item.personal ? " · private" : item.id === workspaceId ? " · selected" : ""}</span></div>)}
      </div>
      {paid && ownedCount < 5 && <form className="workspace-inline-form" onSubmit={(event) => { event.preventDefault(); void act(async () => { const created = await request<Workspace>("/workspaces", json({ name: name.trim() })); onWorkspaceCreated(created.id); }, () => setName("")); }}>
        <div className="workspace-name-field">
          <h3><label htmlFor="new-workspace-name">New workspace name</label></h3>
          <input id="new-workspace-name" value={name} onChange={(event) => setName(event.target.value)} minLength={3} maxLength={80} required placeholder="Team or project name" />
        </div>
        <button className="button primary" disabled={busy || name.trim().length < 3}>Create workspace</button>
      </form>}
      {!paid && <p className="muted small">A paid HackTricks Tools membership is required to create shared workspaces.</p>}
      {paid && ownedCount >= 5 && <p className="muted small">You have created the maximum of five shared workspaces.</p>}
    </>}
    <div className="table-toolbar">
      <h3>Invitations</h3>
      {!invitations.error && !!invitations.data?.items.length && <TableDownload table="workspace-invitations" label="workspace invitations"
        rows={invitations.data.items.map(item => ({ workspace_id: item.workspace_id, name: item.name, role: item.role }))} />}
    </div>
    {invitations.isPending ? <State loading /> : invitations.error ? <State error={invitations.error} onRetry={() => void invitations.refetch()} /> : invitations.data?.items.length ? <>
      {invitations.data.items.map((item) => <div className="workspace-person" key={item.workspace_id}>
      <div><strong>{item.name}</strong><span>{item.role[0].toUpperCase() + item.role.slice(1)} access</span></div>
      <div className="button-row"><button className="button primary" disabled={busy} onClick={() => void act(() => request(`/workspaces/invitations/${encodeURIComponent(item.workspace_id)}/accept`, { method: "POST" }))}>Accept</button><button className="button" disabled={busy} onClick={() => void act(() => request(`/workspaces/invitations/${encodeURIComponent(item.workspace_id)}/decline`, { method: "POST" }))}>Decline</button></div>
    </div>)}</> : <p className="muted small">No pending invitations.</p>}
    {current && !current.personal && current.role === "admin" && <>
      <div className="table-toolbar">
        <h3>People in {current.name}</h3>
        {!people.error && people.data && <TableDownload table="workspace-people" label="workspace people" rows={[
          ...(people.data?.members || []).map(item => ({ user_id: item.user_id,
            email: item.email || "Workspace owner", role: item.role,
            status: item.user_id === current.owner ? "owner" : "member" })),
          ...(people.data?.invitations || []).map(item => ({ user_id: item.user_id,
            email: item.email, role: item.role, status: "invitation_pending" })),
        ]} />}
      </div>
      <p className="muted small">Invite up to 100 existing HackTricks Tools accounts. They can access this workspace only after accepting in Settings.</p>
      <form className="workspace-inline-form" onSubmit={(event) => { event.preventDefault(); void act(() => request(`/workspaces/${encodeURIComponent(workspaceId)}/invitations`, json({ email: email.trim(), role })), () => setEmail("")); }}>
        <label>Account email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required placeholder="person@example.com" /></label>
        <label>Role<select value={role} onChange={(event) => setRole(event.target.value as Role)}>{roles.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select></label>
        <button className="button primary" disabled={busy || !email.trim()}>Invite</button>
      </form>
      {people.isPending ? <State loading /> : people.error ? <State error={people.error} onRetry={() => void people.refetch()} /> : <>
        {people.data?.members.map((member) => <div className="workspace-person" key={member.user_id}>
          <div><strong>{member.email || "Workspace owner"}</strong><span>{member.user_id === current.owner ? "Owner" : "Member"}</span></div>
          {member.user_id === current.owner ? <span>Admin</span> : <div className="button-row"><select aria-label={`Role for ${member.email}`} value={member.role} disabled={busy} onChange={(event) => void act(() => request(`/workspaces/${encodeURIComponent(workspaceId)}/members/${encodeURIComponent(member.user_id)}`, json({ role: event.target.value }, "PATCH")))}>{roles.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select><button className="button" disabled={busy} onClick={() => void act(() => request(`/workspaces/${encodeURIComponent(workspaceId)}/members/${encodeURIComponent(member.user_id)}`, { method: "DELETE" }))}>Remove</button></div>}
        </div>)}
        {people.data?.invitations.map((invite) => <div className="workspace-person" key={invite.user_id}><div><strong>{invite.email}</strong><span>Invitation pending · {invite.role}</span></div><button className="button" disabled={busy} onClick={() => void act(() => request(`/workspaces/${encodeURIComponent(workspaceId)}/invitations/${encodeURIComponent(invite.user_id)}`, { method: "DELETE" }))}>Cancel invitation</button></div>)}
      </>}
    </>}
    {error && <p className="workspace-error" role="alert">{error}</p>}
    {message && <p className="muted small" role="status">{message}</p>}
  </Panel>;
}
