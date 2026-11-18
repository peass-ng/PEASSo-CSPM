import { leakKeys } from "./foundSecretValue";
import type { Finding } from "./types";
const profiles: Record<string, readonly [string,string,string]> = {
  "azure.review.function.selected_package_source_secret_indicators": ["azure","package_source_assertions","the selected stored deployment package"],
  "gcp.review.function.literal_environment_secret_indicators": ["gcp","function_secret_pairs","the function’s literal environment values"],
};
const object = (v: unknown): v is Record<string,unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const cmp = (a:string,b:string) => a < b ? -1 : a > b ? 1 : 0;
const versions: Record<string,string> = { kingfisher:"1.4.0", trufflehog:"3.92.5" };
type Detector = {engine:string;rule:string};
type Location = {path:string;line?:number;scope?:string;resource_id?:string};
type Leak = {fingerprint:string;detectors:Detector[];locations:Location[]};
function validatedLeaks(value:unknown): Leak[] | undefined {
  if (!Array.isArray(value) || value.length > 1024) return;
  const result:Leak[]=[];
  for (const row of value) {
    if (!object(row) || leakKeys(row) !== "detectors,fingerprint,locations" || typeof row.fingerprint !== "string"
        || !/^[0-9a-f]{64}$/.test(row.fingerprint) || !Array.isArray(row.detectors) || !row.detectors.length || row.detectors.length>128
        || !Array.isArray(row.locations) || !row.locations.length || row.locations.length>4096) return;
    const detectors:Detector[]=[], locations:Location[]=[];
    for (const d of row.detectors) {
      if (!object(d) || Object.keys(d).sort().join() !== "engine,rule" || typeof d.engine !== "string" || !Object.keys(versions).includes(d.engine)
          || typeof d.rule !== "string" || !/^[A-Za-z0-9_.:/ -]{1,160}$/.test(d.rule)) return;
      detectors.push({engine:d.engine,rule:d.rule});
    }
    for (const l of row.locations) {
      if (!object(l) || typeof l.path !== "string" || !l.path.length || l.path.length>4096
          || Object.keys(l).some(k => !["path","line","scope","resource_id"].includes(k))
          || ("line" in l && (typeof l.line !== "number" || !Number.isInteger(l.line) || l.line<1))
          || ["scope","resource_id"].some(k => k in l && (typeof l[k] !== "string" || !(l[k] as string).length || (l[k] as string).length>4096))) return;
      locations.push(l as Location);
    }
    if (new Set(detectors.map(d=>JSON.stringify(d))).size!==detectors.length
        || new Set(locations.map(l=>JSON.stringify(l))).size!==locations.length
        || result.some(r=>r.fingerprint===row.fingerprint)) return;
    result.push({fingerprint:row.fingerprint,detectors,locations});
  }
  return result;
}
function canonical(rows:Leak[]): string {
  const merged = new Map<string,{detectors:Map<string,Detector>;locations:Map<string,Location>}>();
  for (const row of rows) {
    const out=merged.get(row.fingerprint)||{detectors:new Map(),locations:new Map()};
    for (const d of row.detectors) out.detectors.set(JSON.stringify([d.engine,d.rule]),d);
    for (const l of row.locations) {
      const loc:Location={path:l.path};
      if (l.line!==undefined) loc.line=l.line;
      if (l.resource_id!==undefined) loc.resource_id=l.resource_id;
      if (l.scope!==undefined) loc.scope=l.scope;
      out.locations.set(JSON.stringify(loc),loc);
    }
    merged.set(row.fingerprint,out);
  }
  return JSON.stringify([...merged].sort(([a],[b])=>cmp(a,b)).map(([fingerprint,row])=>({fingerprint,
    detectors:[...row.detectors.values()].sort((a,b)=>cmp(a.engine,b.engine)||cmp(a.rule,b.rule)),
    locations:[...row.locations.values()].sort((a,b)=>cmp(JSON.stringify(a),JSON.stringify(b)))})));
}

/** Preserve the actual one-leak DTO and its incomplete source observations. */
export function publicSourceSecretObservation(f:Finding): string | undefined {
  const profile=profiles[f.check_id], e=f.evidence;
  if (!profile || f.provider!==profile[0] || f.status!=="FAIL" || !object(e)
      || f.linked_check_ids?.length!==1 || f.linked_check_ids[0]!==f.check_id
      || typeof f.secret_fingerprint!=="string" || !/^[0-9a-f]{64}$/.test(f.secret_fingerprint)
      || f.resource_id!=="secret:"+f.secret_fingerprint || e.credential_validation!=="not_attempted") return;
  const records=e[profile[1]], global=validatedLeaks(e.secret_leaks), leaks:Leak[]=[];
  if (!Array.isArray(records) || !records.length || records.length>1024 || global?.length!==1
      || global[0].fingerprint!==f.secret_fingerprint) return;
  let incomplete=e.complete===false;
  for (const record of records) {
    if (!object(record) || record.check_id!==f.check_id || typeof record.complete!=="boolean"
        || typeof record.scope!=="string" || typeof record.resource_id!=="string") return;
    incomplete ||= !record.complete || record.inventory_complete===false;
    let sections:unknown[], field:string;
    if (profile[0]==="azure") {
      if (!/^\/subscriptions\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(record.scope)
          || !/^sha256:[0-9a-f]{64}$/.test(record.resource_id) || record.cloud_authenticity!=="not_established"
          || record.credential_validation!=="not_attempted" || record.coverage!=="selected_configured_stored_package_only"
          || record.runtime_bytes!=="unknown" || !Array.isArray(record.parts)) return;
      sections=record.parts;field="leaks";
    } else {
      if (record.schema!=="gcp-function-literal-secrets-v2" || !/^projects\/[A-Za-z0-9_-]+$/.test(record.scope)
          || !record.resource_id.startsWith(record.scope+"/locations/")
          || !/^projects\/[A-Za-z0-9_-]+\/locations\/[a-z0-9-]+\/functions\/[A-Za-z0-9_-]+$/.test(record.resource_id)
          || !["serviceConfig","buildConfig"].includes(String(record.surface))) return;
      sections=[record];field="secret_leaks";
    }
    if (!sections.length || sections.length>128) return;
    for (const section of sections) {
      if (!object(section) || typeof section.complete!=="boolean" || !Array.isArray(section.engines) || section.engines.length!==2) return;
      const seen=new Set<string>(), completed=new Set<string>();
      for (const engine of section.engines) {
        if (!object(engine) || Object.keys(engine).sort().join()!=="engine,status,version" || typeof engine.engine!=="string"
            || versions[engine.engine]!==engine.version || !["complete","unavailable"].includes(String(engine.status))) return;
        seen.add(engine.engine);if (engine.status==="complete") completed.add(engine.engine);
      }
      if (seen.size!==2 || section.complete!==(completed.size===2) || (record.complete && !section.complete)) return;
      const local=validatedLeaks(section[field]);
      if (!local?.length) return;
      for (const leak of local) {
        if (leak.fingerprint!==f.secret_fingerprint || leak.detectors.some(d=>!completed.has(d.engine))) return;
        const locations:Location[]=[];
        for (const loc of leak.locations) {
          if (loc.scope!==undefined || loc.resource_id!==undefined) return;
          if (profile[0]==="gcp" ? loc.path!==record.surface+".environmentVariables"
            : loc.path!==section.path || !/^azure_storage_selected_source:[0-9a-f]{64}\.file-[1-9][0-9]{0,2}$/.test(loc.path)) return;
          locations.push({...loc,scope:record.scope,resource_id:record.resource_id});
        }
        leaks.push({...leak,locations});
      }
    }
  }
  if (canonical(leaks)!==canonical(global) || (e.complete===true && incomplete)) return;
  return `A likely secret was detected in ${profile[2]}. It was not validated`
    +(incomplete ? "; inspection is incomplete." : ".");
}
