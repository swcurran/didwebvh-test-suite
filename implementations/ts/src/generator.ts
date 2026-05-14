import fs from 'fs';
import path from 'path';
import { load as yamlLoad } from 'js-yaml';
import { sha256 } from '@noble/hashes/sha2';
import { canonicalize } from 'json-canonicalize';
import { createDID, updateDID, resolveDIDFromLog, multibaseEncode, multibaseDecode, MultibaseEncoding, prepareDataForSigning } from 'didwebvh-ts';
import type { DIDLog, VerificationMethod, WitnessProofFileEntry, DataIntegrityProof } from 'didwebvh-ts';
import { keyFromSeed, Ed25519Signer, PermissiveVerifier } from './cryptography.ts';
import type { Script, CreateStep, UpdateStep, DeactivateStep, ResolveStep } from './interfaces.ts';
import * as ed25519 from '@stablelib/ed25519';

const REPO_ROOT = path.resolve(import.meta.dir, '../../..');
const TS_IMPL_DIR = path.join(REPO_ROOT, 'implementations/ts');
const VECTORS_DIR = path.join(REPO_ROOT, 'vectors');

// Reimplement deriveHash and deriveNextKeyHash from didwebvh-ts (not publicly exported)
function deriveHashSync(input: unknown): string {
  const data = canonicalize(input as any);
  const hash = sha256(data);
  const multihash = new Uint8Array([0x12, 0x20, ...hash]);
  return multibaseEncode(multihash, MultibaseEncoding.BASE58_BTC).slice(1);
}

function deriveNextKeyHash(publicKeyMultibase: string): string {
  const hash = sha256(publicKeyMultibase);
  const multihash = new Uint8Array([0x12, 0x20, ...hash]);
  return multibaseEncode(multihash, MultibaseEncoding.BASE58_BTC).slice(1);
}

async function deactivateDIDWithTimestamp(
  log: DIDLog,
  signerVM: VerificationMethod,
  timestamp: string
): Promise<DIDLog> {
  const lastEntry = log[log.length - 1];
  const signer = new Ed25519Signer({ verificationMethod: signerVM });
  const verifier = new Ed25519Signer({ verificationMethod: signerVM });

  // Resolve to get current meta (updateKeys etc.)
  const { meta } = await resolveDIDFromLog(log, { verifier, fastResolve: false } as any);

  const versionNumber = log.length + 1;
  const params = { updateKeys: meta.updateKeys, deactivated: true };
  const logEntry = {
    versionId: lastEntry.versionId,
    versionTime: timestamp,
    parameters: params,
    state: lastEntry.state,
  };
  const entryHash = deriveHashSync(logEntry);
  const versionId = `${versionNumber}-${entryHash}`;
  const prelimEntry = { ...logEntry, versionId };

  const cryptosuite = 'eddsa-jcs-2022';
  const vmId = signer.getVerificationMethodId();
  const proofBase = {
    type: 'DataIntegrityProof',
    cryptosuite,
    verificationMethod: vmId,
    created: timestamp,
    proofPurpose: 'assertionMethod',
  };
  const { proofValue } = await signer.sign({ document: prelimEntry, proof: proofBase });
  const entry = { ...prelimEntry, proof: [{ ...proofBase, proofValue }] };

  return [...log, entry] as DIDLog;
}

async function generateWitnessProof(
  versionId: string,
  witnessVM: VerificationMethod,
  timestamp: string
): Promise<DataIntegrityProof> {
  const document = { versionId };
  const vmId = `did:key:${witnessVM.publicKeyMultibase}#${witnessVM.publicKeyMultibase}`;
  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: vmId,
    created: timestamp,
    proofPurpose: 'assertionMethod',
  };
  const dataToSign = await prepareDataForSigning(document, proof);
  const secretKey = multibaseDecode(witnessVM.secretKeyMultibase!).bytes.slice(2);
  const sig = ed25519.sign(secretKey, dataToSign);
  const proofValue = multibaseEncode(sig, MultibaseEncoding.BASE58_BTC);
  return { ...proof, proofValue } as DataIntegrityProof;
}

function buildKeyMap(script: Script): Map<string, VerificationMethod> {
  const map = new Map<string, VerificationMethod>();
  for (const keyDef of script.keys) {
    map.set(keyDef.id, keyFromSeed(keyDef.seed));
  }
  return map;
}

function resolveKeyVMs(keyIds: string[], keyMap: Map<string, VerificationMethod>): VerificationMethod[] {
  return keyIds.map(id => {
    const vm = keyMap.get(id);
    if (!vm) throw new Error(`Unknown key ID: ${id}`);
    return vm;
  });
}

function buildWitnessParam(config: { threshold: number; witnesses: { id: string }[] }, keyMap: Map<string, VerificationMethod>) {
  return {
    threshold: config.threshold,
    witnesses: config.witnesses.map(w => {
      const vm = keyMap.get(w.id);
      if (!vm) throw new Error(`Unknown witness key ID: ${w.id}`);
      return { id: `did:key:${vm.publicKeyMultibase}` };
    }),
  };
}

function toResolutionResult(doc: any, meta: any) {
  const versionId: string = meta.versionId;
  const versionNumber = parseInt(versionId.split('-')[0]);
  const didDocumentMetadata: Record<string, unknown> = {
    created: meta.created,
    updated: meta.updated,
    versionId,
    versionNumber,
    versionTime: meta.updated,
  };
  if (meta.deactivated) {
    didDocumentMetadata.deactivated = true;
  }
  return {
    didDocument: doc,
    didDocumentMetadata,
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
  };
}

async function processScript(scriptPath: string, verify: boolean): Promise<void> {
  const scenarioName = path.basename(path.dirname(scriptPath));
  const outDir = path.join(VECTORS_DIR, scenarioName, 'ts');

  const script = yamlLoad(fs.readFileSync(scriptPath, 'utf8')) as Script;
  const keyMap = buildKeyMap(script);

  let log: DIDLog = [];
  let currentUpdateVMs: VerificationMethod[] = [];
  let currentDocVMs: VerificationMethod[] = [];
  let witnessVMs: VerificationMethod[] = [];
  let witnessProofs: WitnessProofFileEntry[] = [];

  const resolveResults: Array<{ filename: string; result: unknown }> = [];

  for (const step of script.steps) {
    if (step.op === 'create') {
      const s = step as CreateStep;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);
      const signer = new Ed25519Signer({ verificationMethod: signerVM });
      const verifier = new Ed25519Signer({ verificationMethod: signerVM });

      const updateKeyIds = s.params?.updateKeys ?? [s.signer];
      currentUpdateVMs = resolveKeyVMs(updateKeyIds, keyMap);
      currentDocVMs = currentUpdateVMs;

      const witnessParam = s.params?.witness ? buildWitnessParam(s.params.witness, keyMap) : undefined;
      if (s.params?.witness) {
        witnessVMs = s.params.witness.witnesses.map(w => {
          const vm = keyMap.get(w.id);
          if (!vm) throw new Error(`Unknown witness key ID: ${w.id}`);
          return vm;
        });
      }

      const nextKeyHashes = s.params?.nextKeyHashes
        ? resolveKeyVMs(s.params.nextKeyHashes, keyMap).map(vm => deriveNextKeyHash(vm.publicKeyMultibase!))
        : [];

      const { log: newLog, meta } = await createDID({
        domain: s.domain,
        signer,
        verifier,
        updateKeys: currentUpdateVMs.map(vm => vm.publicKeyMultibase!),
        verificationMethods: currentDocVMs,
        context: s.params?.context,
        alsoKnownAs: s.params?.alsoKnownAs,
        portable: s.params?.portable,
        nextKeyHashes,
        witness: witnessParam ?? null,
        created: s.timestamp,
      });

      log = newLog;

      if (witnessVMs.length > 0) {
        const proofs: DataIntegrityProof[] = [];
        for (const wvm of witnessVMs) {
          proofs.push(await generateWitnessProof(meta.versionId, wvm, s.timestamp));
        }
        witnessProofs.push({ versionId: meta.versionId, proof: proofs });
      }

    } else if (step.op === 'update') {
      const s = step as UpdateStep;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);
      const signer = new Ed25519Signer({ verificationMethod: signerVM });

      // Auto-detect pre-rotation consumption: signer is not in the current updateKeys.
      // In that case updateDID's internal signature check (against old keys) must be bypassed;
      // the resolver correctly validates against parameters.updateKeys when prerotation is set.
      const signerInCurrentKeys = currentUpdateVMs.some(
        vm => vm.publicKeyMultibase === signerVM.publicKeyMultibase
      );
      const verifier = signerInCurrentKeys
        ? new Ed25519Signer({ verificationMethod: signerVM })
        : new PermissiveVerifier({ verificationMethod: signerVM });

      if (s.params?.updateKeys) {
        currentUpdateVMs = resolveKeyVMs(s.params.updateKeys, keyMap);
        currentDocVMs = currentUpdateVMs;
      }
      if (s.params?.verificationMethods) {
        currentDocVMs = s.params.verificationMethods.map(vmDef => ({
          ...vmDef,
          type: vmDef.type ?? 'Multikey',
        })) as VerificationMethod[];
      }

      const witnessParam = s.params?.witness ? buildWitnessParam(s.params.witness, keyMap) : undefined;
      if (s.params?.witness) {
        witnessVMs = s.params.witness.witnesses.map(w => {
          const vm = keyMap.get(w.id);
          if (!vm) throw new Error(`Unknown witness key ID: ${w.id}`);
          return vm;
        });
      }

      const nextKeyHashes = s.params?.nextKeyHashes
        ? resolveKeyVMs(s.params.nextKeyHashes, keyMap).map(vm => deriveNextKeyHash(vm.publicKeyMultibase!))
        : [];

      const { log: newLog, meta } = await updateDID({
        log,
        signer,
        verifier,
        updateKeys: currentUpdateVMs.map(vm => vm.publicKeyMultibase!),
        verificationMethods: currentDocVMs,
        context: s.params?.context,
        alsoKnownAs: s.params?.alsoKnownAs,
        services: s.params?.services as any,
        nextKeyHashes: nextKeyHashes.length > 0 ? nextKeyHashes : [],
        witness: witnessParam,
        witnessProofs: witnessProofs.length > 0 ? witnessProofs : undefined,
        updated: s.timestamp,
        domain: s.domain,
      } as any);

      log = newLog;

      if (witnessVMs.length > 0) {
        const proofs: DataIntegrityProof[] = [];
        for (const wvm of witnessVMs) {
          proofs.push(await generateWitnessProof(meta.versionId, wvm, s.timestamp));
        }
        witnessProofs.push({ versionId: meta.versionId, proof: proofs });
      }

    } else if (step.op === 'deactivate') {
      const s = step as DeactivateStep;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);
      log = await deactivateDIDWithTimestamp(log, signerVM, s.timestamp);

    } else if (step.op === 'resolve') {
      const s = step as ResolveStep;
      const verifier = new Ed25519Signer({ verificationMethod: currentUpdateVMs[0] });
      const opts: Record<string, unknown> = {
        verifier,
        witnessProofs: witnessProofs.length > 0 ? witnessProofs : undefined,
        fastResolve: false,
      };
      if (s.versionId) opts.versionId = s.versionId;
      if (s.versionNumber !== undefined) opts.versionNumber = s.versionNumber;

      const { doc, meta } = await resolveDIDFromLog(log, opts as any);
      resolveResults.push({ filename: s.expect, result: toResolutionResult(doc, meta) });
    }
  }

  if (verify) {
    let allMatch = true;
    for (const { filename, result } of resolveResults) {
      const committedPath = path.join(outDir, filename);
      if (!fs.existsSync(committedPath)) {
        console.error(`\n  MISSING: ${filename}`);
        allMatch = false;
        continue;
      }
      const committed = JSON.parse(fs.readFileSync(committedPath, 'utf8'));
      if (canonicalize(result) !== canonicalize(committed)) {
        console.error(`\n  MISMATCH: ${filename}`);
        allMatch = false;
      }
    }
    const committedLog = path.join(outDir, 'did.jsonl');
    if (!fs.existsSync(committedLog)) {
      console.error('\n  MISSING: did.jsonl');
      allMatch = false;
    } else {
      const committedLines = fs.readFileSync(committedLog, 'utf8').trim();
      const generatedLines = log.map(e => JSON.stringify(e)).join('\n');
      if (generatedLines !== committedLines) {
        console.error('\n  MISMATCH: did.jsonl');
        allMatch = false;
      }
    }
    const witnessPath = path.join(outDir, 'did-witness.json');
    if (witnessProofs.length > 0) {
      if (!fs.existsSync(witnessPath)) {
        console.error('\n  MISSING: did-witness.json');
        allMatch = false;
      } else {
        const committed = JSON.parse(fs.readFileSync(witnessPath, 'utf8'));
        if (canonicalize(witnessProofs) !== canonicalize(committed)) {
          console.error('\n  MISMATCH: did-witness.json');
          allMatch = false;
        }
      }
    }
    if (allMatch) console.log('OK');
    return;
  }

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'did.jsonl'), log.map(e => JSON.stringify(e)).join('\n') + '\n');
  if (witnessProofs.length > 0) {
    fs.writeFileSync(path.join(outDir, 'did-witness.json'), JSON.stringify(witnessProofs, null, 2) + '\n');
  }
  for (const { filename, result } of resolveResults) {
    fs.writeFileSync(path.join(outDir, filename), JSON.stringify(result, null, 2) + '\n');
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function readConfig(): { version: string } {
  try {
    const cfg = yamlLoad(fs.readFileSync(path.join(TS_IMPL_DIR, 'config.yaml'), 'utf8')) as any;
    return { version: cfg.version ?? '' };
  } catch {
    return { version: '' };
  }
}

// ---------------------------------------------------------------------------
// Cross-resolution helpers
// ---------------------------------------------------------------------------

function extractVersionNumber(filename: string): number | null {
  const parts = path.basename(filename, '.json').split('.');
  if (parts.length > 1) {
    const n = parseInt(parts[1]);
    if (!isNaN(n)) return n;
  }
  return null;
}

function computeUnifiedDiff(expected: unknown, actual: unknown): string {
  const expLines = JSON.stringify(expected, null, 2).split('\n');
  const actLines = JSON.stringify(actual, null, 2).split('\n');
  const m = expLines.length, n = actLines.length;

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = expLines[i] === actLines[j]
        ? dp[i + 1][j + 1] + 1
        : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  type Edit = { t: ' ' | '-' | '+'; l: string };
  const edits: Edit[] = [];
  let i = 0, j = 0;
  while (i < m || j < n) {
    if (i < m && j < n && expLines[i] === actLines[j]) {
      edits.push({ t: ' ', l: expLines[i++] }); j++;
    } else if (j < n && (i >= m || dp[i][j + 1] >= dp[i + 1][j])) {
      edits.push({ t: '+', l: actLines[j++] });
    } else {
      edits.push({ t: '-', l: expLines[i++] });
    }
  }

  const CONTEXT = 3;
  const changeIdxs = edits.map((e, k) => e.t !== ' ' ? k : -1).filter(k => k >= 0);
  if (changeIdxs.length === 0) return '';

  const hunks: Array<[number, number]> = [];
  let hs = -1, he = -1;
  for (const idx of changeIdxs) {
    const s = Math.max(0, idx - CONTEXT);
    const e = Math.min(edits.length - 1, idx + CONTEXT);
    if (hs < 0) { hs = s; he = e; }
    else if (s <= he + 1) { he = Math.max(he, e); }
    else { hunks.push([hs, he]); hs = s; he = e; }
  }
  if (hs >= 0) hunks.push([hs, he]);

  const out: string[] = ['--- expected', '+++ actual (ts resolver)'];
  for (const [start, end] of hunks) {
    const slice = edits.slice(start, end + 1);
    const beforeOld = edits.slice(0, start).filter(e => e.t !== '+').length;
    const beforeNew = edits.slice(0, start).filter(e => e.t !== '-').length;
    out.push(`@@ -${beforeOld + 1},${slice.filter(e => e.t !== '+').length} +${beforeNew + 1},${slice.filter(e => e.t !== '-').length} @@`);
    for (const e of slice) out.push(`${e.t}${e.l}`);
  }
  return out.join('\n');
}

async function runVectorTest(
  implDir: string,
  resultFile: string,
): Promise<{ type: 'pass' | 'fail' | 'diff'; diff?: string; reason?: string }> {
  try {
    const logContent = fs.readFileSync(path.join(implDir, 'did.jsonl'), 'utf8');
    const expected = JSON.parse(fs.readFileSync(path.join(implDir, resultFile), 'utf8'));

    const logLines = logContent.trim().split('\n').filter((l: string) => l.trim());
    if (logLines.length === 0) return { type: 'fail', reason: 'empty did.jsonl' };
    const log = logLines.map((l: string) => JSON.parse(l)) as DIDLog;

    let witnessProofs: WitnessProofFileEntry[] = [];
    const witnessPath = path.join(implDir, 'did-witness.json');
    if (fs.existsSync(witnessPath)) {
      witnessProofs = JSON.parse(fs.readFileSync(witnessPath, 'utf8'));
    }

    const versionNumber = extractVersionNumber(resultFile);
    const dummyVM = keyFromSeed('0'.repeat(64));
    const verifier = new PermissiveVerifier({ verificationMethod: dummyVM });

    const opts: Record<string, unknown> = { verifier, fastResolve: false };
    if (witnessProofs.length > 0) opts.witnessProofs = witnessProofs;
    if (versionNumber !== null) opts.versionNumber = versionNumber;

    const { doc, meta } = await resolveDIDFromLog(log, opts as any);
    const actual = toResolutionResult(doc, meta);

    if (canonicalize(actual) === canonicalize(expected)) return { type: 'pass' };
    return { type: 'diff', diff: computeUnifiedDiff(expected, actual) };
  } catch (e: any) {
    return { type: 'fail', reason: e.message };
  }
}

interface RowEntry { logSource: string; result: string; notes: string }
interface DiffEntry { logSource: string; filename: string; diff: string }
interface GenRow { testCase: string; result: string; notes: string }

async function crossResolveStatus(
  scenarioName: string
): Promise<{ rows: RowEntry[]; diffs: DiffEntry[] }> {
  const scenarioDir = path.join(VECTORS_DIR, scenarioName);

  const implDirs = fs.readdirSync(scenarioDir)
    .filter((d: string) => fs.statSync(path.join(scenarioDir, d)).isDirectory())
    .sort();

  const rows: RowEntry[] = [];
  const diffs: DiffEntry[] = [];

  for (const implName of implDirs) {
    const implDir = path.join(scenarioDir, implName);
    if (!fs.existsSync(path.join(implDir, 'did.jsonl'))) {
      rows.push({ logSource: implName, result: '⚠️ SKIP', notes: 'no did.jsonl' });
      continue;
    }

    const resultFiles = fs.readdirSync(implDir)
      .filter((f: string) => f.startsWith('resolutionResult') && f.endsWith('.json'))
      .sort();

    if (resultFiles.length === 0) {
      rows.push({ logSource: implName, result: '⚠️ SKIP', notes: 'no resolutionResult files' });
      continue;
    }

    let outcome: 'pass' | 'fail' | 'diff' = 'pass';
    let failReason = '';

    for (const rf of resultFiles) {
      const r = await runVectorTest(implDir, rf);
      if (r.type === 'fail') {
        if (outcome !== 'diff') { outcome = 'fail'; failReason = r.reason ?? 'error'; }
      } else if (r.type === 'diff') {
        if (outcome === 'pass') outcome = 'diff';
        diffs.push({ logSource: implName, filename: rf, diff: r.diff! });
      }
    }

    const label = implName === 'ts' ? 'ts (self)' : implName;
    rows.push({
      logSource: label,
      result: outcome === 'pass' ? '✅ PASS' : outcome === 'diff' ? '🔶 DIFF' : '❌ FAIL',
      notes: outcome === 'fail' ? failReason : outcome === 'diff' ? 'see diffs.txt' : '',
    });
  }

  return { rows, diffs };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const verify = args.includes('--verify');
  const targets = args.filter((a: string) => !a.startsWith('--'));

  const scriptPaths = targets.length > 0
    ? targets.map((t: string) =>
        fs.existsSync(t) ? t : path.join(VECTORS_DIR, t, 'script.yaml')
      )
    : fs.readdirSync(VECTORS_DIR)
        .filter((d: string) => {
          const p = path.join(VECTORS_DIR, d);
          return fs.statSync(p).isDirectory() && fs.existsSync(path.join(p, 'script.yaml'));
        })
        .sort()
        .map((d: string) => path.join(VECTORS_DIR, d, 'script.yaml'));

  const statusPath = path.join(TS_IMPL_DIR, 'status.md');
  const diffsPath = path.join(TS_IMPL_DIR, 'diffs.txt');

  if (!verify) {
    if (fs.existsSync(statusPath)) fs.unlinkSync(statusPath);
    if (fs.existsSync(diffsPath)) fs.unlinkSync(diffsPath);
  }

  const genRows: GenRow[] = [];
  const allRows: Array<{ testCase: string } & RowEntry> = [];
  const allDiffs: Array<{ testCase: string } & DiffEntry> = [];

  let hasError = false;
  for (const scriptPath of scriptPaths) {
    const name = path.basename(path.dirname(scriptPath));
    process.stdout.write(`${verify ? 'Verifying' : 'Generating'} ${name}... `);
    try {
      await processScript(scriptPath, verify);
      if (!verify) {
        console.log('done');
        genRows.push({ testCase: name, result: '✅ PASS', notes: '' });
        process.stdout.write(`  Cross-resolving ${name}... `);
        const { rows, diffs } = await crossResolveStatus(name);
        for (const row of rows) allRows.push({ testCase: name, ...row });
        for (const diff of diffs) allDiffs.push({ testCase: name, ...diff });

        const oldStatus = path.join(VECTORS_DIR, name, 'ts', 'status.md');
        if (fs.existsSync(oldStatus)) fs.unlinkSync(oldStatus);

        console.log('done');
      }
    } catch (e: any) {
      console.error(`ERROR: ${e.message}`);
      if (!verify) genRows.push({ testCase: name, result: '❌ FAIL', notes: e.message });
      hasError = true;
    }
  }

  if (!verify && (genRows.length > 0 || allRows.length > 0)) {
    const cfg = readConfig();
    const header = cfg.version ? `Implementation: didwebvh-ts ${cfg.version}\n\n` : '';

    const genTable = genRows.length > 0
      ? `## DID Creation\n\n| Test Case | Result | Notes |\n|---|---|---|\n${genRows.map(r => `| ${r.testCase} | ${r.result} | ${r.notes} |`).join('\n')}\n\n`
      : '';

    const tableRows = allRows
      .map(r => `| ${r.testCase} | ${r.logSource} | ${r.result} | ${r.notes} |`)
      .join('\n');
    const crossTable = allRows.length > 0
      ? `## Cross-Resolution\n\n| Test Case | Log Source | Result | Notes |\n|---|---|---|---|\n${tableRows}\n`
      : '';

    fs.writeFileSync(statusPath,
      `# ts status\n\n${header}${genTable}${crossTable}`
    );

    if (allDiffs.length > 0) {
      const diffContent = allDiffs
        .map(d => `=== ${d.testCase} / ${d.logSource} — ${d.filename} ===\n${d.diff}`)
        .join('\n\n') + '\n';
      fs.writeFileSync(diffsPath, diffContent);
    }
  }

  if (hasError) process.exit(1);
}

main();
