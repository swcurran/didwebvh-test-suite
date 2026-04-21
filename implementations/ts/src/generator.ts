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
const SCRIPTS_DIR = path.join(REPO_ROOT, 'scripts');
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
  const scriptName = path.basename(scriptPath, '.yaml');
  const outDir = path.join(VECTORS_DIR, scriptName);

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
      if (JSON.stringify(result, null, 2) !== JSON.stringify(committed, null, 2)) {
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
        if (JSON.stringify(witnessProofs, null, 2) !== JSON.stringify(committed, null, 2)) {
          console.error('\n  MISMATCH: did-witness.json');
          allMatch = false;
        }
      }
    }
    if (allMatch) console.log('OK');
    return;
  }

  fs.mkdirSync(outDir, { recursive: true });
  fs.copyFileSync(scriptPath, path.join(outDir, 'script.yaml'));
  fs.writeFileSync(path.join(outDir, 'did.jsonl'), log.map(e => JSON.stringify(e)).join('\n') + '\n');
  if (witnessProofs.length > 0) {
    fs.writeFileSync(path.join(outDir, 'did-witness.json'), JSON.stringify(witnessProofs, null, 2) + '\n');
  }
  for (const { filename, result } of resolveResults) {
    fs.writeFileSync(path.join(outDir, filename), JSON.stringify(result, null, 2) + '\n');
  }
}

async function main() {
  const args = process.argv.slice(2);
  const verify = args.includes('--verify');
  const targets = args.filter((a: string) => !a.startsWith('--'));

  const scriptPaths = targets.length > 0
    ? targets
    : fs.readdirSync(SCRIPTS_DIR)
        .filter((f: string) => f.endsWith('.yaml'))
        .sort()
        .map((f: string) => path.join(SCRIPTS_DIR, f));

  let hasError = false;
  for (const scriptPath of scriptPaths) {
    const name = path.basename(scriptPath, '.yaml');
    process.stdout.write(`${verify ? 'Verifying' : 'Generating'} ${name}... `);
    try {
      await processScript(scriptPath, verify);
      if (!verify) console.log('done');
    } catch (e: any) {
      console.error(`ERROR: ${e.message}`);
      hasError = true;
    }
  }
  if (hasError) process.exit(1);
}

main();
