import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { load as yamlLoad } from 'js-yaml';
import { sha256 } from '@noble/hashes/sha2';
import { canonicalize } from 'json-canonicalize';
import { createDID, updateDID, multibaseEncode, multibaseDecode, MultibaseEncoding, prepareDataForSigning } from 'didwebvh-ts';
import type { DIDLog, VerificationMethod, DataIntegrityProof, WitnessProofFileEntry } from 'didwebvh-ts';
import { keyFromSeed, Ed25519Signer, PermissiveVerifier } from './cryptography.ts';
import type { KeyDef, CreateStep, UpdateStep, StepParams } from './interfaces.ts';
// KeyDef used via NegativeScript.keys below
import * as ed25519 from '@stablelib/ed25519';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const VECTORS_DIR = path.join(REPO_ROOT, 'vectors');

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

// Extended step types for negative tests
interface CorruptOp {
  op: 'corrupt';
  entry: number;           // 0-indexed log entry
  mutation: string;
  field?: string;
  value?: unknown;
  when: 'before-sign' | 'after-sign';
}

interface MigrateOp {
  op: 'migrate';
  domain: string;
  signer: string;
  timestamp: string;
  params?: StepParams;
}

interface SignWitnessProofOp {
  op: 'sign-witness-proof';
  signer: string;   // witness key ID
  entry: number;    // 0-indexed log entry whose versionId to sign
}

interface ResolveDIDOp {
  op: 'resolve-did';
  did: string;
  expectError: string;
}

interface ResolveErrorOp {
  op: 'resolve';
  expectError: string;
}

type NegativeStep = CreateStep | UpdateStep | CorruptOp | MigrateOp | SignWitnessProofOp | ResolveDIDOp | ResolveErrorOp;

interface NegativeScript {
  description: string;
  spec_ref?: string;
  negative?: boolean;
  keys: KeyDef[];
  steps: NegativeStep[];
}

interface LogEntryLike {
  versionId: string;
  versionTime: string;
  parameters: Record<string, unknown>;
  state: Record<string, unknown>;
  proof?: DataIntegrityProof[];
}

function buildKeyMap(keys: KeyDef[]): Map<string, VerificationMethod> {
  const map = new Map<string, VerificationMethod>();
  for (const keyDef of keys) {
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

function toResolutionError(error: string) {
  return {
    didDocument: null,
    didDocumentMetadata: {},
    didResolutionMetadata: { error },
  };
}

// "key-attacker" → "KEY_ATTACKER" (hyphens→underscores, uppercase)
// Placeholder in script: {KEY_ATTACKER} — the key ID itself encodes the name.
function keyIdToPlaceholder(keyId: string): string {
  return `{${keyId.replace(/-/g, '_').toUpperCase()}}`;
}

// Placeholders expand to the raw public key multibase so that the script
// template controls surrounding context (e.g. "did:key:{KEY_ATTACKER}#{KEY_AUTHORIZED}").
function substituteKeyPlaceholders(value: unknown, keyMap: Map<string, VerificationMethod>): unknown {
  if (typeof value !== 'string') return value;
  let result = value;
  for (const [keyId, vm] of keyMap) {
    result = result.replaceAll(keyIdToPlaceholder(keyId), vm.publicKeyMultibase!);
  }
  return result;
}

function applyMutation(
  entry: LogEntryLike,
  mutation: string,
  field?: string,
  value?: unknown,
  keyMap?: Map<string, VerificationMethod>
): LogEntryLike {
  const mutated = JSON.parse(JSON.stringify(entry)) as LogEntryLike;
  const substitutedValue = keyMap ? substituteKeyPlaceholders(value, keyMap) : value;

  switch (mutation) {
    case 'replace-state-id-scid': {
      // DID format: did:webvh:SCID:domain  →  parts[2] is the SCID
      const id = mutated.state.id as string;
      const parts = id.split(':');
      if (parts.length >= 3) {
        parts[2] = substitutedValue as string;
        mutated.state.id = parts.join(':');
      }
      break;
    }
    case 'replace-version-time': {
      mutated.versionTime = substitutedValue as string;
      break;
    }
    case 'replace-parameter': {
      const paramName = field ?? (value as string);
      if (paramName) {
        mutated.parameters[paramName] = substitutedValue;
      }
      break;
    }
    case 'drop-parameter': {
      // Scripts may use either `field:` or `value:` to name the parameter to drop
      const paramName = field ?? (value as string);
      if (paramName) {
        delete mutated.parameters[paramName];
      }
      break;
    }
    case 'replace-proof-field': {
      if (mutated.proof && mutated.proof.length > 0 && field) {
        mutated.proof[0] = { ...mutated.proof[0], [field]: substitutedValue };
      }
      break;
    }
    default:
      throw new Error(`Unknown mutation: ${mutation}`);
  }

  return mutated;
}

async function resignEntry(
  entry: LogEntryLike,
  entryIndex: number,
  log: DIDLog,
  signerVM: VerificationMethod,
): Promise<LogEntryLike> {
  // The hash input for entry N uses the versionId of entry N-1 as its own
  // versionId field (this is how the did:webvh hash chain is constructed).
  // For the genesis entry (index 0) the "previous" versionId is the SCID.
  const prevVersionId = entryIndex === 0
    ? entry.parameters.scid as string
    : (log[entryIndex - 1] as any).versionId as string;

  const hashInput = {
    versionId: prevVersionId,
    versionTime: entry.versionTime,
    parameters: entry.parameters,
    state: entry.state,
  };
  const entryHash = deriveHashSync(hashInput);
  const versionNumber = parseInt(entry.versionId.split('-')[0]);
  const newVersionId = `${versionNumber}-${entryHash}`;

  // The proof is computed over the preliminary entry (which carries the new versionId)
  const prelimEntry = {
    versionId: newVersionId,
    versionTime: entry.versionTime,
    parameters: entry.parameters,
    state: entry.state,
  };

  const cryptosuite = 'eddsa-jcs-2022';
  const vmId = `did:key:${signerVM.publicKeyMultibase}#${signerVM.publicKeyMultibase}`;
  const proofBase = {
    type: 'DataIntegrityProof',
    cryptosuite,
    verificationMethod: vmId,
    created: entry.versionTime,
    proofPurpose: 'assertionMethod',
  };

  const secretKey = multibaseDecode(signerVM.secretKeyMultibase!).bytes.slice(2);
  const dataToSign = await prepareDataForSigning(prelimEntry as any, proofBase as any);
  const sig = ed25519.sign(secretKey, dataToSign);
  const proofValue = multibaseEncode(sig, MultibaseEncoding.BASE58_BTC);

  return {
    versionId: newVersionId,
    versionTime: entry.versionTime,
    parameters: entry.parameters,
    state: entry.state,
    proof: [{ ...proofBase, proofValue } as DataIntegrityProof],
  };
}

// Builds a genesis log entry manually, bypassing library validation.
// Used as a fallback when createDID rejects intentionally invalid parameters
// (e.g. duplicate witness IDs, zero threshold) that the negative test needs.
// The SCID derivation follows the same algorithm as the library:
//   scid = hash(initialEntry with {SCID} placeholder)
//   prelimEntry = initialEntry.replaceAll('{SCID}', scid)
//   versionId = "1-" + hash(prelimEntry)
async function createGenesisBypass(
  domain: string,
  timestamp: string,
  updateKeyVMs: VerificationMethod[],
  signerVM: VerificationMethod,
  witnessParam: unknown,
  nextKeyHashes: string[],
  portable: boolean,
): Promise<DIDLog> {
  const updateKeys = updateKeyVMs.map(vm => vm.publicKeyMultibase!);

  const vmIdSuffix = (pubkey: string) => pubkey.slice(-8);

  const verificationMethods = updateKeyVMs.map(vm => ({
    type: 'Multikey',
    publicKeyMultibase: vm.publicKeyMultibase,
    purpose: 'authentication',
    id: `did:webvh:{SCID}:${domain}#${vmIdSuffix(vm.publicKeyMultibase!)}`,
  }));

  const initialEntry = {
    versionId: '{SCID}',
    versionTime: timestamp,
    parameters: {
      method: 'did:webvh:1.0',
      scid: '{SCID}',
      updateKeys,
      portable,
      nextKeyHashes,
      watchers: [],
      witness: witnessParam ?? {},
      deactivated: false,
    },
    state: {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
      ],
      id: `did:webvh:{SCID}:${domain}`,
      controller: `did:webvh:{SCID}:${domain}`,
      verificationMethod: verificationMethods,
      authentication: verificationMethods.map(vm => vm.id),
      assertionMethod: [],
      keyAgreement: [],
      capabilityDelegation: [],
      capabilityInvocation: [],
    },
  };

  const scid = deriveHashSync(initialEntry);
  const prelimEntry = JSON.parse(JSON.stringify(initialEntry).replaceAll('{SCID}', scid));
  const entryHash = deriveHashSync(prelimEntry);
  const versionId = `1-${entryHash}`;
  const finalEntry = { ...prelimEntry, versionId };

  const cryptosuite = 'eddsa-jcs-2022';
  const vmId = `did:key:${signerVM.publicKeyMultibase}#${signerVM.publicKeyMultibase}`;
  const proofBase = {
    type: 'DataIntegrityProof',
    cryptosuite,
    verificationMethod: vmId,
    created: timestamp,
    proofPurpose: 'assertionMethod',
  };

  const secretKey = multibaseDecode(signerVM.secretKeyMultibase!).bytes.slice(2);
  const dataToSign = await prepareDataForSigning(finalEntry as any, proofBase as any);
  const sig = ed25519.sign(secretKey, dataToSign);
  const proofValue = multibaseEncode(sig, MultibaseEncoding.BASE58_BTC);

  return [{ ...finalEntry, proof: [{ ...proofBase, proofValue }] }] as DIDLog;
}

// Builds an update log entry manually, bypassing library-side authorization
// checks (e.g. updateDID's hard rejection of updateKeys that don't hash into
// the previous entry's nextKeyHashes commitment). Used as a fallback when
// updateDID rejects intentionally invalid parameters that the negative test
// needs to carry through to resolution.
async function updateEntryBypass(
  log: DIDLog,
  timestamp: string,
  parameters: Record<string, unknown>,
  state: Record<string, unknown>,
  signerVM: VerificationMethod,
): Promise<DIDLog> {
  const prevEntry = log[log.length - 1] as any;
  const versionNumber = log.length + 1;

  const hashInput = { versionId: prevEntry.versionId, versionTime: timestamp, parameters, state };
  const entryHash = deriveHashSync(hashInput);
  const versionId = `${versionNumber}-${entryHash}`;
  const prelimEntry = { versionId, versionTime: timestamp, parameters, state };

  const cryptosuite = 'eddsa-jcs-2022';
  const vmId = `did:key:${signerVM.publicKeyMultibase}#${signerVM.publicKeyMultibase}`;
  const proofBase = {
    type: 'DataIntegrityProof',
    cryptosuite,
    verificationMethod: vmId,
    created: timestamp,
    proofPurpose: 'assertionMethod',
  };

  const secretKey = multibaseDecode(signerVM.secretKeyMultibase!).bytes.slice(2);
  const dataToSign = await prepareDataForSigning(prelimEntry as any, proofBase as any);
  const sig = ed25519.sign(secretKey, dataToSign);
  const proofValue = multibaseEncode(sig, MultibaseEncoding.BASE58_BTC);

  return [...log, { ...prelimEntry, proof: [{ ...proofBase, proofValue }] }] as DIDLog;
}

// Returns the given ISO-8601 timestamp advanced by one second, as a fallback
// when the library rejects a timestamp that equals the previous entry's time.
function bumpTimestamp(ts: string): string {
  const d = new Date(ts);
  d.setUTCSeconds(d.getUTCSeconds() + 1);
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

async function processNegativeScript(scriptPath: string): Promise<void> {
  const scenarioName = path.basename(path.dirname(scriptPath));
  const outDir = path.join(VECTORS_DIR, scenarioName, 'ts');

  const script = yamlLoad(fs.readFileSync(scriptPath, 'utf8')) as NegativeScript;

  if (!script.negative) return;

  // Scripts using multi-DID ops (did_label) require generator extensions not yet implemented.
  const hasUnimplementedOps = script.steps.some(step =>
    (step as any).did_label !== undefined
  );
  if (hasUnimplementedOps) {
    console.log(`  (skipped: uses unimplemented ops)`);
    return;
  }

  const keyMap = script.keys?.length ? buildKeyMap(script.keys) : new Map<string, VerificationMethod>();
  let log: DIDLog = [];
  let currentUpdateVMs: VerificationMethod[] = [];
  let currentWitnessVMs: VerificationMethod[] = [];
  // Valid witness proofs generated after each log entry so that updateDID's
  // internal resolveDIDFromLog can resolve the preceding entries.  These are
  // separate from the (potentially malicious) witnessProofs written to disk.
  let constructionWitnessProofs: WitnessProofFileEntry[] = [];
  let expectError: string | null = null;
  let witnessProofs: WitnessProofFileEntry[] = [];

  for (const step of script.steps) {
    if (step.op === 'create') {
      const s = step as CreateStep;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);
      const signer = new Ed25519Signer({ verificationMethod: signerVM });
      const verifier = new Ed25519Signer({ verificationMethod: signerVM });

      const updateKeyIds = s.params?.updateKeys ?? [s.signer];
      currentUpdateVMs = resolveKeyVMs(updateKeyIds, keyMap);

      const nextKeyHashes = s.params?.nextKeyHashes
        ? resolveKeyVMs(s.params.nextKeyHashes, keyMap).map(vm => deriveNextKeyHash(vm.publicKeyMultibase!))
        : [];

      const witnessParam = s.params?.witness ? buildWitnessParam(s.params.witness, keyMap) : undefined;
      if (s.params?.witness) {
        currentWitnessVMs = s.params.witness.witnesses.map(w => {
          const vm = keyMap.get(w.id);
          if (!vm) throw new Error(`Unknown witness key ID: ${w.id}`);
          return vm;
        });
      } else {
        currentWitnessVMs = [];
      }

      let newLog: DIDLog;
      try {
        ({ log: newLog } = await createDID({
          address: s.domain,
          signer,
          verifier,
          updateKeys: currentUpdateVMs.map(vm => vm.publicKeyMultibase!),
          verificationMethods: currentUpdateVMs,
          context: s.params?.context,
          alsoKnownAs: s.params?.alsoKnownAs,
          portable: s.params?.portable,
          nextKeyHashes,
          witness: witnessParam ?? null,
          created: s.timestamp,
        }));
      } catch {
        // Library rejected the parameters (e.g. duplicate witness IDs, zero threshold).
        // Build the genesis entry manually so negative tests can carry the invalid config.
        newLog = await createGenesisBypass(
          s.domain,
          s.timestamp,
          currentUpdateVMs,
          signerVM,
          witnessParam,
          nextKeyHashes,
          s.params?.portable ?? false,
        );
      }

      // A second create resets the log (multiple-scenario scripts)
      log = newLog;
      constructionWitnessProofs = [];
      if (witnessParam && currentWitnessVMs.length > 0) {
        const entry = log[log.length - 1] as any;
        for (const wvm of currentWitnessVMs) {
          const vmId = `did:key:${wvm.publicKeyMultibase}#${wvm.publicKeyMultibase}`;
          const proofBase = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: vmId, created: entry.versionTime, proofPurpose: 'assertionMethod' };
          const sk = multibaseDecode(wvm.secretKeyMultibase!).bytes.slice(2);
          const sig = ed25519.sign(sk, await prepareDataForSigning({ versionId: entry.versionId } as any, proofBase as any));
          constructionWitnessProofs.push({ versionId: entry.versionId, proof: [{ ...proofBase, proofValue: multibaseEncode(sig, MultibaseEncoding.BASE58_BTC) } as DataIntegrityProof] });
        }
      }

    } else if (step.op === 'update') {
      const s = step as UpdateStep;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);

      // Always use PermissiveVerifier in the negative generator so library-internal
      // key checks don't block intentionally malformed scenarios.
      const verifier = new PermissiveVerifier({ verificationMethod: signerVM });
      const signer = new Ed25519Signer({ verificationMethod: signerVM });

      if (s.params?.updateKeys) {
        currentUpdateVMs = resolveKeyVMs(s.params.updateKeys, keyMap);
      }

      const nextKeyHashes = s.params?.nextKeyHashes
        ? resolveKeyVMs(s.params.nextKeyHashes, keyMap).map(vm => deriveNextKeyHash(vm.publicKeyMultibase!))
        : [];

      const witnessParam = s.params?.witness ? buildWitnessParam(s.params.witness, keyMap) : undefined;

      // The library may reject timestamps that are not strictly later than the
      // previous entry.  If it does, retry with a bumped timestamp — a
      // subsequent corrupt step will overwrite the value before re-signing.
      let updateTimestamp = s.timestamp;
      let newLog: DIDLog;
      const updateOpts = {
        log,
        signer,
        verifier,
        updateKeys: currentUpdateVMs.map(vm => vm.publicKeyMultibase!),
        verificationMethods: currentUpdateVMs,
        context: s.params?.context,
        alsoKnownAs: s.params?.alsoKnownAs,
        services: s.params?.services as any,
        nextKeyHashes: nextKeyHashes.length > 0 ? nextKeyHashes : [],
        witness: witnessParam,
        witnessProofs: constructionWitnessProofs.length > 0 ? constructionWitnessProofs : undefined,
        address: s.domain,
      };
      try {
        ({ log: newLog } = await updateDID({ ...updateOpts, updated: updateTimestamp } as any));
      } catch {
        updateTimestamp = bumpTimestamp(updateTimestamp);
        try {
          ({ log: newLog } = await updateDID({ ...updateOpts, updated: updateTimestamp } as any));
        } catch {
          // Library hard-rejects some intentionally invalid updates (e.g. updateKeys
          // that don't hash into the previous entry's nextKeyHashes commitment) even
          // with a permissive verifier. Build the entry manually instead.
          const prevState = (log[log.length - 1] as any).state;
          const parameters: Record<string, unknown> = {
            updateKeys: updateOpts.updateKeys,
            nextKeyHashes: updateOpts.nextKeyHashes,
            witness: updateOpts.witness ?? {},
            watchers: [],
          };
          newLog = await updateEntryBypass(log, updateTimestamp, parameters, prevState, signerVM);
        }
      }
      log = newLog;

    } else if (step.op === 'migrate') {
      const s = step as MigrateOp;
      const signerVM = keyMap.get(s.signer);
      if (!signerVM) throw new Error(`Unknown signer key: ${s.signer}`);
      const verifier = new PermissiveVerifier({ verificationMethod: signerVM });
      const signer = new Ed25519Signer({ verificationMethod: signerVM });

      if (s.params?.updateKeys) {
        currentUpdateVMs = resolveKeyVMs(s.params.updateKeys, keyMap);
      }

      let migrateTimestamp = s.timestamp;
      let newLog: DIDLog;
      const migrateOpts = {
        log,
        signer,
        verifier,
        updateKeys: currentUpdateVMs.map(vm => vm.publicKeyMultibase!),
        verificationMethods: currentUpdateVMs,
        witnessProofs: constructionWitnessProofs.length > 0 ? constructionWitnessProofs : undefined,
        address: s.domain,
      };
      try {
        ({ log: newLog } = await updateDID({ ...migrateOpts, updated: migrateTimestamp } as any));
      } catch {
        migrateTimestamp = bumpTimestamp(migrateTimestamp);
        ({ log: newLog } = await updateDID({ ...migrateOpts, updated: migrateTimestamp } as any));
      }
      log = newLog;

    } else if (step.op === 'corrupt') {
      const s = step as CorruptOp;
      const entryIdx = s.entry;
      if (entryIdx < 0 || entryIdx >= log.length) {
        throw new Error(`corrupt: entry index ${s.entry} out of range [0, ${log.length - 1}]`);
      }

      const signerVM = currentUpdateVMs.length > 0
        ? currentUpdateVMs[0]
        : Array.from(keyMap.values())[0];

      const entry = log[entryIdx] as LogEntryLike;
      const mutated = applyMutation(entry, s.mutation, s.field, s.value, keyMap);

      if (s.when === 'before-sign') {
        const resigned = await resignEntry(mutated, entryIdx, log, signerVM);
        log[entryIdx] = resigned as any;
      } else {
        // after-sign: mutate the signed entry without re-signing
        log[entryIdx] = mutated as any;
      }

    } else if (step.op === 'sign-witness-proof') {
      const s = step as SignWitnessProofOp;
      const witnessVM = keyMap.get(s.signer);
      if (!witnessVM) throw new Error(`Unknown witness key: ${s.signer}`);
      const entryIdx = s.entry;
      if (entryIdx < 0 || entryIdx >= log.length) {
        throw new Error(`sign-witness-proof: entry index ${entryIdx} out of range [0, ${log.length - 1}]`);
      }
      const versionId = (log[entryIdx] as any).versionId as string;
      const timestamp = (log[entryIdx] as any).versionTime as string;
      const vmId = `did:key:${witnessVM.publicKeyMultibase}#${witnessVM.publicKeyMultibase}`;
      const proofBase = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: vmId,
        created: timestamp,
        proofPurpose: 'assertionMethod',
      };
      const secretKey = multibaseDecode(witnessVM.secretKeyMultibase!).bytes.slice(2);
      const dataToSign = await prepareDataForSigning({ versionId } as any, proofBase as any);
      const sig = ed25519.sign(secretKey, dataToSign);
      const proofValue = multibaseEncode(sig, MultibaseEncoding.BASE58_BTC);
      witnessProofs.push({ versionId, proof: [{ ...proofBase, proofValue } as DataIntegrityProof] });

    } else if (step.op === 'resolve' || step.op === 'resolve-did') {
      // Both op types record the expected error; the harness reads the script
      // for actual DID URLs in the resolve-did case.
      expectError = (step as ResolveErrorOp | ResolveDIDOp).expectError ?? null;
    }
  }

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, 'did.jsonl'),
    log.length > 0 ? log.map(e => JSON.stringify(e)).join('\n') + '\n' : ''
  );

  if (witnessProofs.length > 0) {
    fs.writeFileSync(
      path.join(outDir, 'did-witness.json'),
      JSON.stringify(witnessProofs, null, 2) + '\n'
    );
  }

  if (expectError) {
    fs.writeFileSync(
      path.join(outDir, 'resolutionResult.json'),
      JSON.stringify(toResolutionError(expectError), null, 2) + '\n'
    );
  }
}

async function main() {
  const entries = fs.readdirSync(VECTORS_DIR);

  for (const entry of entries) {
    if (!entry.startsWith('negative-')) continue;

    const scenarioDir = path.join(VECTORS_DIR, entry);
    const scriptPath = path.join(scenarioDir, 'script.yaml');
    if (!fs.existsSync(scriptPath)) continue;

    process.stdout.write(`Generating ${entry}... `);
    try {
      await processNegativeScript(scriptPath);
      console.log('done');
    } catch (e) {
      console.error(`ERROR: ${e}`);
      process.exit(1);
    }
  }

  console.log('\nDone.');
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
