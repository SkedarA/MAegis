import { CaseWorkspace } from "../../case-workspace";

export default async function IncidentWorkspacePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <CaseWorkspace incidentId={id} />;
}
