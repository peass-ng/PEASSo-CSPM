import { Download } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { downloadFindingsPdf } from "./api";

export function FindingsPdfDownload({ id, path }: { id: string; path: string }) {
  const running = useRef<AbortController | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => () => running.current?.abort(), []);

  async function download() {
    if (running.current) return;
    const task = new AbortController();
    running.current = task;
    setPending(true);
    setError("");
    try {
      await downloadFindingsPdf(path, id, task.signal);
    } catch (failure) {
      if (!task.signal.aborted)
        setError(failure instanceof Error ? failure.message : "Report PDF could not be downloaded.");
    } finally {
      running.current = null;
      if (!task.signal.aborted) setPending(false);
    }
  }

  return <div className="findings-pdf-download">
    <button type="button" className="button" aria-busy={pending} disabled={pending} onClick={() => void download()}>
      <Download size={15} aria-hidden="true" /> {pending ? "Preparing PDF…" : "Download PDF"}
    </button>
    {error && <p role="alert" className="form-error">{error}</p>}
  </div>;
}
