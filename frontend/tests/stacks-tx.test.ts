import { describe, it, expect } from 'vitest';
import { getNetwork } from '../src/lib/stacks-tx';

describe('stacks-tx library', () => {
    it('returns testnet by default', () => {
        const network = getNetwork();
        expect(network.isMainnet()).toBe(false);
    });

    it('returns mainnet when requested', () => {
        const network = getNetwork(true);
        expect(network.isMainnet()).toBe(true);
    });
});
