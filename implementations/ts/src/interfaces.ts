export interface KeyDef {
  id: string;
  type: 'ed25519';
  seed: string; // 32-byte hex
}

export interface WitnessEntry {
  id: string; // key ID from the keys section
  weight?: number;
}

export interface WitnessConfig {
  threshold: number;
  witnesses: WitnessEntry[];
}

export interface ServiceDef {
  id: string;
  type: string | string[];
  serviceEndpoint: string | string[] | Record<string, unknown>;
}

export interface VerificationMethodDef {
  id?: string;
  type?: string;
  controller?: string;
  publicKeyMultibase?: string;
  purpose?: 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation';
}

export interface StepParams {
  updateKeys?: string[];       // key IDs from the keys section
  nextKeyHashes?: string[];    // key IDs whose hashes to commit
  witness?: WitnessConfig;
  portable?: boolean;
  context?: string[];
  alsoKnownAs?: string[];
  services?: ServiceDef[];
  verificationMethods?: VerificationMethodDef[];
}

export interface CreateStep {
  op: 'create';
  domain: string;
  signer: string;  // key ID
  timestamp: string;
  params?: StepParams;
}

export interface UpdateStep {
  op: 'update';
  signer: string;  // key ID
  timestamp: string;
  domain?: string; // for portable DID domain migration
  params?: StepParams;
}

export interface DeactivateStep {
  op: 'deactivate';
  signer: string;  // key ID
  timestamp: string;
}

export interface ResolveStep {
  op: 'resolve';
  versionId?: string;
  versionNumber?: number;
  expect: string;  // output filename, e.g. "resolutionResult.json"
}

export type Step = CreateStep | UpdateStep | DeactivateStep | ResolveStep;

export interface Script {
  description: string;
  spec_ref?: string;
  keys: KeyDef[];
  steps: Step[];
}
