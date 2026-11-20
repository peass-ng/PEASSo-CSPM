import { Fragment, type ReactNode } from "react";

function inline(text: string) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, index) =>
    part.startsWith("**") && part.endsWith("**") ? <strong key={index}>{inline(part.slice(2, -2))}</strong> :
      part.startsWith("`") && part.endsWith("`") ? <code key={index}>{part.slice(1, -1)}</code> : part);
}

// Render only headings, paragraphs and lists. React escapes all source text;
// model output never becomes HTML or executable Markdown.
export function NetworkArchitecture({ text, label = "Network architecture", markdown = false }: { text: string; label?: string; markdown?: boolean }) {
  const blocks = text.split(/\n\s*\n/).filter(block => block.trim());
  const structured = markdown || blocks.some(block => /^#{2,4}\s/m.test(block));
  return <section className="network-architecture" aria-label={label}>{blocks.map((block, index) => {
    if (structured) {
      const lines = block.trim().split('\n');
      if (lines.every(line => /^\d+[.)]\s/.test(line))) return <ol key={index}>{lines.map((line, item) => <li key={item}>{inline(line.replace(/^\d+[.)]\s/, ''))}</li>)}</ol>;
      if (lines.every(line => /^[-*]\s/.test(line))) return <ul key={index}>{lines.map((line, item) => <li key={item}>{inline(line.replace(/^[-*]\s/, ''))}</li>)}</ul>;
      return <Fragment key={index}>{lines.map((line, item) => {
        if (/^#{2,3}\s/.test(line)) return <h3 key={item}>{inline(line.replace(/^#{2,3}\s/, ''))}</h3>;
        if (/^####\s/.test(line)) return <h4 key={item}>{inline(line.replace(/^####\s/, ''))}</h4>;
        return <p key={item}>{inline(line)}</p>;
      })}</Fragment>;
    }
    // Older scans contain a whole VPC in one paragraph. Preserve every word,
    // but split that block into readable groups without inventing tier labels.
    const boundary = block.match(/^([^\n—]{1,120})\s—\s/);
    const body = boundary ? block.slice(boundary[0].length) : block;
    const sentences = body.split(/(?<=[.!?])\s+(?=[A-Z])/);
    const content: ReactNode[] = [];
    let paragraph = "";
    let count = 0;
    const tiers = new Set<string>();
    function flush() {
      if (paragraph) content.push(<p key={`p-${content.length}`}>{paragraph}</p>);
      paragraph = "";
      count = 0;
    }
    for (const sentence of sentences) {
      // Use a tier label only when the original prose explicitly names it.
      const tier = sentence.match(/^(?:The|Its)\s+((?:public|private|database|application)(?:\s+[\w-]+){0,2}\s+tier)\b/i)?.[1];
      if (tier && !tiers.has(tier.toLowerCase())) {
        flush();
        content.push(<h4 key={`h-${content.length}`}>{tier[0].toUpperCase() + tier.slice(1)}</h4>);
        tiers.add(tier.toLowerCase());
      }
      if (paragraph && (count === 2 || paragraph.length + sentence.length > 420)) flush();
      paragraph += (paragraph ? " " : "") + sentence;
      count++;
    }
    flush();
    return <article className="network-boundary" key={index}>{boundary && <h3>{boundary[1].trim()}</h3>}{content}</article>;
  })}</section>;
}
