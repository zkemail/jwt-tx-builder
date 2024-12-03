import { createMerkleTree, verifyMerkleProof, MerkleTree } from '../src/merkle-tree';

describe('MerkleTree', () => {
  // Helper function to create test data
  const createTestLeaves = () => [1n, 2n, 3n, 4n];

  describe('Tree Creation', () => {
    it('should create a tree with correct height', async () => {
      const leaves = createTestLeaves();
      const tree = await createMerkleTree(2, leaves);
      expect(tree).toBeInstanceOf(MerkleTree);
    });

    it('should handle empty leaves', async () => {
      const tree = await createMerkleTree(2, []);
      expect(tree).toBeInstanceOf(MerkleTree);
    });

    it('should pad leaves to correct size', async () => {
      const leaves = [1n, 2n]; // Only 2 leaves for height 2 (needs 4)
      const tree = await createMerkleTree(2, leaves);
      expect(tree).toBeInstanceOf(MerkleTree);
    });
  });

  describe('Root Calculation', () => {
    it('should calculate consistent root for same leaves', async () => {
      const leaves = createTestLeaves();
      const tree1 = await createMerkleTree(2, leaves);
      const tree2 = await createMerkleTree(2, leaves);

      expect(tree1.getRoot()).toEqual(tree2.getRoot());
    });

    it('should calculate different roots for different leaves', async () => {
      const leaves1 = [1n, 2n, 3n, 4n];
      const leaves2 = [1n, 2n, 3n, 5n]; // Last leaf different

      const tree1 = await createMerkleTree(2, leaves1);
      const tree2 = await createMerkleTree(2, leaves2);

      expect(tree1.getRoot()).not.toEqual(tree2.getRoot());
    });
  });

  describe('Proof Generation and Verification', () => {
    it('should generate valid proof for existing leaf', async () => {
      const leaves = createTestLeaves();
      const tree = await createMerkleTree(2, leaves);
      const root = tree.getRoot();

      // Test proof for each leaf
      for (let i = 0; i < leaves.length; i++) {
        const { proof, pathIndices } = tree.getProof(i);
        const isValid = await verifyMerkleProof(leaves[i], proof, pathIndices, root);
        expect(isValid).toBe(true);
      }
    });

    it('should reject proof for non-existent leaf', async () => {
      const leaves = createTestLeaves();
      const tree = await createMerkleTree(2, leaves);
      const root = tree.getRoot();

      // Get proof for leaf at index 0
      const { proof, pathIndices } = tree.getProof(0);

      // Try to verify with wrong leaf value
      const isValid = await verifyMerkleProof(
        99n, // Wrong leaf value
        proof,
        pathIndices,
        root,
      );
      expect(isValid).toBe(false);
    });

    it('should reject proof with tampered path indices', async () => {
      const leaves = createTestLeaves();
      const tree = await createMerkleTree(2, leaves);
      const root = tree.getRoot();

      const { proof, pathIndices } = tree.getProof(0);

      // Tamper with path indices
      const tamperedPathIndices = [...pathIndices];
      tamperedPathIndices[0] = tamperedPathIndices[0] === 0 ? 1 : 0;

      const isValid = await verifyMerkleProof(leaves[0], proof, tamperedPathIndices, root);
      expect(isValid).toBe(false);
    });

    it('should reject proof with tampered proof elements', async () => {
      const leaves = createTestLeaves();
      const tree = await createMerkleTree(2, leaves);
      const root = tree.getRoot();

      const { proof, pathIndices } = tree.getProof(0);

      // Tamper with proof elements
      const tamperedProof = [...proof];
      tamperedProof[0] = 999n;

      const isValid = await verifyMerkleProof(leaves[0], tamperedProof, pathIndices, root);
      expect(isValid).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle single leaf tree', async () => {
      const tree = await createMerkleTree(1, [1n]);
      const { proof, pathIndices } = tree.getProof(0);
      const isValid = await verifyMerkleProof(1n, proof, pathIndices, tree.getRoot());
      expect(isValid).toBe(true);
    });

    it('should handle maximum supported tree height', async () => {
      const height = 10; // Adjust based on your implementation's limits
      const leaves = [1n, 2n];
      const tree = await createMerkleTree(height, leaves);
      const { proof, pathIndices } = tree.getProof(0);
      const isValid = await verifyMerkleProof(1n, proof, pathIndices, tree.getRoot());
      expect(isValid).toBe(true);
    });
  });
});
