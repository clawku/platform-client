export type ApprovalRequest = {
  jobId: string;
  command: string;
  args?: string[];
  cwd?: string;
  requestedBy?: string;
};

export type ApprovalDecision = {
  jobId: string;
  approved: boolean;
  reason?: string;
};

// Placeholder for native notification / modal integration
export async function requestApproval(req: ApprovalRequest): Promise<ApprovalDecision> {
  // TODO: replace with native notification flow
  const approved = window.confirm(
    `Allow command?\n\n${req.command} ${(req.args || []).join(' ')}\n\nRequested by: ${req.requestedBy || 'unknown'}`
  );
  return { jobId: req.jobId, approved };
}
