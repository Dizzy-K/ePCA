import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT=path.resolve(ROOT,'build/reproduction/evidence');
const sources={adaptive:'results/phase4_v2_canonical3/adaptive_raw.jsonl',pcc:'results/phase4_v2_pcc_canonical/pcc_llm_raw.jsonl',deterministic:'results/phase2_v2/raw_results.jsonl'};
const digest=s=>crypto.createHash('sha256').update(s).digest('hex');
const stable=x=>JSON.stringify(sort(x));
function sort(x){if(Array.isArray(x))return x.map(sort);if(x&&typeof x==='object')return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])]));return x;}
const counts=xs=>Object.fromEntries([...xs.reduce((m,x)=>m.set(x,(m.get(x)||0)+1),new Map())].sort());
const mean=xs=>xs.length?xs.reduce((a,b)=>a+b,0)/xs.length:null;
const quantile=(xs,p)=>{const ys=[...xs].sort((a,b)=>a-b);return ys[Math.ceil(p*ys.length)-1]??null;};
const src={};const data={};for(const [k,p]of Object.entries(sources)){const b=await fs.readFile(ROOT+'/'+p);src[k]={path:p,sha256:digest(b)};data[k]=b.toString().trim().split('\n').map(JSON.parse);}
const models=['gpt-5.5','deepseek-v4-pro'];
const pcc=data.pcc.filter(r=>models.includes(r.model));
if(pcc.length!==720||data.adaptive.length!==720)throw new Error('Canonical cohort changed');
// The archived provider-normalized schema uses input/output, not SDK field names.
// Missing usage must be reported as missing, never silently converted to zero.
for(const r of pcc){
 if(!Number.isFinite(r.token_usage?.input)||!Number.isFinite(r.token_usage?.output))throw new Error(`Missing token usage in ${r.call_id}`);
 r.token_usage={...r.token_usage,input_tokens:r.token_usage.input,output_tokens:r.token_usage.output};
}
const tuples=new Map();
for(const r of pcc){const a={...r.action};delete a.session_id;const key=stable({environment:r.environment,state:r.state,action:a});if(!tuples.has(key))tuples.set(key,{id:digest(key).slice(0,12),environment:r.environment,kind:r.safe_or_unsafe,state:r.state,action:a,rows:[]});tuples.get(key).rows.push(r);}
const semantic=[...tuples.values()].sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id)).map(t=>({...t,rows:undefined,models:Object.fromEntries(models.map(m=>{const rs=t.rows.filter(r=>r.model===m);return[m,{calls:rs.length,pairIDs:new Set(rs.map(r=>r.pair_id)).size,pccAccepted:rs.filter(r=>r.certificate_valid).length,epcaAccepted:rs.filter(r=>r.epca_accepted).length,reasons:counts(rs.filter(r=>!r.certificate_valid).map(r=>r.failure_reason))}]}))}));
function failureClass(r){const s=r.failure_reason||'';if(s.startsWith('JSONDecodeError'))return'JSON syntax';if(s.startsWith('ValueError'))return'Certificate field or witness type';if(s==='post_state_transition_mismatch')return'Post-state mismatch';if(s==='obligation_set_mismatch')return'Obligation set mismatch';if(s==='invalid_obligation_witness')return'Invalid obligation witness';if(s==='safety_obligation_failed')return'Violated safety obligation';return'Binding mismatch';}
const pccSummary=models.map(model=>{const rs=pcc.filter(r=>r.model===model),safe=rs.filter(r=>r.safe_or_unsafe==='safe'),unsafe=rs.filter(r=>r.safe_or_unsafe==='unsafe');const st=semantic.filter(t=>t.kind==='safe');return{model,calls:rs.length,apiErrors:rs.filter(r=>r.api_error).length,safeAccepted:safe.filter(r=>r.certificate_valid).length,safeCalls:safe.length,unsafeAccepted:unsafe.filter(r=>r.certificate_valid).length,unsafeCalls:unsafe.length,epcaSafeAccepted:safe.filter(r=>r.epca_accepted).length,semanticSafeMacroAcceptance:mean(st.map(t=>t.models[model].pccAccepted/t.models[model].calls)),safeFailureClasses:counts(safe.filter(r=>!r.certificate_valid).map(failureClass)),safeFailureReasons:counts(safe.filter(r=>!r.certificate_valid).map(r=>r.failure_reason)),temperature:counts(rs.map(r=>r.temperature)),maxTokens:counts(rs.map(r=>r.max_tokens)),provider:counts(rs.map(r=>r.provider)),dates:counts(rs.map(r=>r.date?.slice(0,10))),generationMeanMs:mean(rs.map(r=>r.generation_latency)),generationP95Ms:quantile(rs.map(r=>r.generation_latency),.95),safeE2EMeanMs:mean(safe.map(r=>r.end_to_end_latency)),safeLocalEpcaMeanMs:mean(safe.map(r=>r.epca_verification_latency)),meanInputTokens:mean(rs.map(r=>r.token_usage?.input_tokens??r.token_usage?.prompt_tokens??0)),meanOutputTokens:mean(rs.map(r=>r.token_usage?.output_tokens??r.token_usage?.completion_tokens??0))};});
const adaptiveSummary=[];for(const model of models)for(const guardrail of ['RuntimeOnly','StatelessRuleFilter','StatefulRuleMonitor','ePCA']){const rs=data.adaptive.filter(r=>r.model===model&&r.guardrail===guardrail);adaptiveSummary.push({model,guardrail,records:rs.length,uniqueEpisodeIDs:new Set(rs.map(r=>r.episode_id)).size,apiErrors:rs.filter(r=>r.api_error).length,complete:rs.filter(r=>r.episode_complete).length,goalTypes:counts(rs.map(r=>r.goal_type)),terminations:counts(rs.map(r=>r.termination_reason)),turnCapReached:rs.filter(r=>r.trajectory_length>=12).length,meanActorLatencyMs:mean(rs.map(r=>r.trajectory.reduce((a,t)=>a+(t.actor_latency_ms||0),0))),feedbackMessages:counts(rs.flatMap(r=>r.trajectory.map(t=>t.agent_feedback))),configHashes:counts(rs.map(r=>r.config_hash))});}
const runtimeRows=data.deterministic.filter(r=>r.condition==='NoGuard');const unsafeSteps=runtimeRows.flatMap(r=>r.steps).filter(t=>t.oracle_safe===false);const runtimeFlow=counts(unsafeSteps.map(t=>`${t.operation} / ${t.decision_reason} / committed=${t.commit_success}`));
const example=data.adaptive.find(r=>r.episode_id==='deepseek-v4-pro::df-indirect-exfiltration::r1::ePCA');if(!example)throw new Error('Missing case');
await fs.mkdir(OUT,{recursive:true});
const output={sources:src,scope:'Existing canonical records only; no model calls or environment execution. Kimi records excluded from this two-model manuscript.',excludedPccModels:counts(data.pcc.filter(r=>!models.includes(r.model)).map(r=>r.model)),pccSummary,semanticCoverage:counts(semantic.map(t=>t.kind)),semanticTuples:semantic,adaptiveSummary,runtimeFlow};
await fs.writeFile(OUT+'/existing_data_analysis.json',JSON.stringify(output,null,2));
await fs.writeFile(OUT+'/dataflow_case.json',JSON.stringify({source:src.adaptive,episode:example},null,2));
let md='# Existing-record reanalysis / 既有记录重分析\n\nNo new experiment or API request. Source hashes are recorded in `existing_data_analysis.json`.\n\n';
md+='## PCC calls and semantic templates\n\n| Model | Safe calls accepted | Unsafe calls accepted | Safe-template macro acceptance | Safe certificate mean E2E (ms) |\n|---|---:|---:|---:|---:|\n';
for(const r of pccSummary)md+=`| ${r.model} | ${r.safeAccepted}/${r.safeCalls} | ${r.unsafeAccepted}/${r.unsafeCalls} | ${(100*r.semanticSafeMacroAcceptance).toFixed(2)}% | ${r.safeE2EMeanMs.toFixed(2)} |\n`;
md+='\nSemantic tuple = environment + trusted pre-state + canonical action, excluding only session_id. Calls and pair IDs are repeated instances, not independent semantic templates. The macro average gives each of the eight safe templates equal weight and is descriptive.\n\n';
md+='| Template | Domain | Kind | Action | GPT accepted/calls | DeepSeek accepted/calls |\n|---|---|---|---|---:|---:|\n';
for(const t of semantic)md+=`| ${t.id} | ${t.environment} | ${t.kind} | ${t.action.action} | ${t.models['gpt-5.5'].pccAccepted}/${t.models['gpt-5.5'].calls} | ${t.models['deepseek-v4-pro'].pccAccepted}/${t.models['deepseek-v4-pro'].calls} |\n`;
md+='\n## Safe-certificate rejection categories\n\nCounts use the first checker/parser rejection, so categories are mutually exclusive.\n\n| Reason | GPT | DeepSeek |\n|---|---:|---:|\n';
for(const k of new Set(pccSummary.flatMap(r=>Object.keys(r.safeFailureClasses))))md+=`| ${k} | ${pccSummary[0].safeFailureClasses[k]||0} | ${pccSummary[1].safeFailureClasses[k]||0} |\n`;
md+='\n## RuntimeOnly unauthorized record flow\n\n| Operation / reason / commit | Records |\n|---|---:|\n';for(const [k,n]of Object.entries(runtimeFlow))md+=`| ${k} | ${n} |\n`;
md+='\nThe remaining 240/520 records exercise schema or shared-executor rejection paths. The concurrency record contains one successful commit and one rejected stale interleaving; its record-level `commit_success` is false. RuntimeOnly bypasses policy authorization, not schema checks or the shared executor.\n\n## Interpretation\n\nThe fixed-call acceptance differences are conditional on these generation configurations and eight safe semantic templates. They do not compare model capability across temperatures or establish unseen-template generalization. Existing logs suffice for this descriptive reanalysis; no additional experiment is proposed or launched under the current scope.\n';
await fs.writeFile(OUT+'/existing_data_analysis.md',md);
console.log(JSON.stringify({pccSummary,coverage:output.semanticCoverage,runtimeFlow},null,2));
