export type QueuedJob = {
  jobId: string;
  command: string;
  args?: string[];
  cwd?: string;
  requestedBy?: string;
  receivedAt: number;
};

export class JobQueue {
  private readonly jobs: QueuedJob[] = [];

  add(job: QueuedJob): void {
    this.jobs.push(job);
  }

  list(): QueuedJob[] {
    return [...this.jobs];
  }

  take(jobId: string): QueuedJob | null {
    const idx = this.jobs.findIndex((j) => j.jobId === jobId);
    if (idx === -1) return null;
    const [job] = this.jobs.splice(idx, 1);
    return job || null;
  }
}
