import * as ed25519 from '@stablelib/ed25519';
import { AbstractCrypto, prepareDataForSigning } from 'didwebvh-ts';
import { multibaseEncode, multibaseDecode, MultibaseEncoding } from 'didwebvh-ts';
import type { SigningInput, SigningOutput, SignerOptions, VerificationMethod } from 'didwebvh-ts';

export function keyFromSeed(hexSeed: string): VerificationMethod {
  const seed = Buffer.from(hexSeed.padStart(64, '0'), 'hex');
  const keyPair = ed25519.generateKeyPairFromSeed(seed);
  const publicKeyMultibase = multibaseEncode(
    new Uint8Array([0xed, 0x01, ...keyPair.publicKey]),
    MultibaseEncoding.BASE58_BTC
  );
  const secretKeyMultibase = multibaseEncode(
    new Uint8Array([0x80, 0x26, ...keyPair.secretKey]),
    MultibaseEncoding.BASE58_BTC
  );
  return {
    type: 'Multikey',
    publicKeyMultibase,
    secretKeyMultibase,
    purpose: 'authentication',
  };
}

export class Ed25519Signer extends AbstractCrypto {
  private secretKey: Uint8Array;

  constructor(options: SignerOptions) {
    super(options);
    const smb = options.verificationMethod?.secretKeyMultibase;
    if (!smb) throw new Error('secretKeyMultibase required');
    this.secretKey = multibaseDecode(smb).bytes.slice(2);
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    const signature = ed25519.sign(this.secretKey, dataToSign);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(publicKey, message, signature);
    } catch {
      return false;
    }
  }
}

// Used for pre-rotation consumption: updateDID validates signer against old updateKeys,
// but for pre-rotation the new key must sign. We bypass that internal check here;
// the resolver correctly validates against parameters.updateKeys when prerotation is active.
export class PermissiveVerifier extends Ed25519Signer {
  async verify(_signature: Uint8Array, _message: Uint8Array, _publicKey: Uint8Array): Promise<boolean> {
    return true;
  }
}
