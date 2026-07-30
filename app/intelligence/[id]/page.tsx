import { CampaignWorkspace } from "../../campaign-workspace";

export default async function CampaignWorkspacePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <CampaignWorkspace campaignId={id} />;
}
