import { describe, it, expect } from 'vitest';
import { Cl } from '@stacks/transactions';

const accounts = simnet.getAccounts();
const DEPLOYER = accounts.get("deployer")!;

describe('biometric-wallet contract', () => {
    it('should initialize with owner pubkey', () => {
        // Example compressed secp256r1 public key (33 bytes)
        const examplePubkey = new Uint8Array(33);
        examplePubkey[0] = 0x02; // Compressed key prefix
        // Fill rest with example data
        for (let i = 1; i < 33; i++) {
            examplePubkey[i] = i;
        }

        const pubKeyBuff = Cl.buffer(examplePubkey);

        const { result } = simnet.callPublicFn(
            'biometric-wallet',
            'initialize',
            [pubKeyBuff],
            DEPLOYER
        );

        expect(result).toBeOk(Cl.bool(true));

        // Verify stored pubkey
        const storedPubkey = simnet.callReadOnlyFn(
            'biometric-wallet',
            'get-owner-pubkey',
            [],
            DEPLOYER
        );
        expect(storedPubkey.result).toBeOk(pubKeyBuff);
    });

    it('should return current nonce', () => {
        const examplePubkey = new Uint8Array(33);
        examplePubkey[0] = 0x02;
        for (let i = 1; i < 33; i++) {
            examplePubkey[i] = i;
        }

        simnet.callPublicFn(
            'biometric-wallet',
            'initialize',
            [Cl.buffer(examplePubkey)],
            DEPLOYER
        );

        const nonceResult = simnet.callReadOnlyFn(
            'biometric-wallet',
            'get-nonce',
            [],
            DEPLOYER
        );

        expect(nonceResult.result).toBeOk(Cl.uint(0));
    });

    it('should verify signature read-only function exists', () => {
        const examplePubkey = new Uint8Array(33);
        examplePubkey[0] = 0x02;
        for (let i = 1; i < 33; i++) {
            examplePubkey[i] = i;
        }

        simnet.callPublicFn(
            'biometric-wallet',
            'initialize',
            [Cl.buffer(examplePubkey)],
            DEPLOYER
        );

        // Test with dummy hash and signature (32 bytes hash, 64 bytes sig)
        const dummyHash = new Uint8Array(32).fill(1);
        const dummySig = new Uint8Array(64).fill(2);

        const verifyResult = simnet.callReadOnlyFn(
            'biometric-wallet',
            'verify-signature',
            [Cl.buffer(dummyHash), Cl.buffer(dummySig)],
            DEPLOYER
        );

        // This will return false since it's not a real signature,
        // but it shows the function is callable
        expect(verifyResult.result).toBeBool(false);
    });

    it('should reject execute-action with invalid signature', () => {
        const examplePubkey = new Uint8Array(33);
        examplePubkey[0] = 0x02;
        for (let i = 1; i < 33; i++) {
            examplePubkey[i] = i;
        }

        simnet.callPublicFn(
            'biometric-wallet',
            'initialize',
            [Cl.buffer(examplePubkey)],
            DEPLOYER
        );

        // Try to execute action with invalid signature
        const actionPayload = new Uint8Array(128).fill(5);
        const invalidSig = new Uint8Array(64).fill(7);

        const executeRes = simnet.callPublicFn(
            'biometric-wallet',
            'execute-action',
            [Cl.buffer(actionPayload), Cl.buffer(invalidSig)],
            DEPLOYER
        );

        // Should fail with ERR-INVALID-SIGNATURE (u100)
        expect(executeRes.result).toBeErr(Cl.uint(100));
    });
});
