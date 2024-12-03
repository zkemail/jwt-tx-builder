import { buildPoseidon } from 'circomlibjs';

export class MerkleTree {
  private readonly height: number;

  private readonly poseidon: any;

  private tree: bigint[][];

  private readonly zeros: bigint[];

  constructor(height: number, leaves: bigint[], poseidon: any) {
    this.height = height;
    this.poseidon = poseidon;

    // Initialize zeros array for padding
    this.zeros = [];
    this.zeros[0] = 0n;
    for (let i = 1; i <= height; i++) {
      const hash = this.poseidon([this.zeros[i - 1], this.zeros[i - 1]]);
      this.zeros[i] = this.poseidon.F.toObject(hash);
    }

    this.tree = this.buildTree(leaves);
  }

  private hashPair(left: bigint, right: bigint): bigint {
    const hash = this.poseidon([left, right]);
    return this.poseidon.F.toObject(hash);
  }

  private buildTree(leaves: bigint[]): bigint[][] {
    const totalLeaves = 2 ** this.height;
    const paddedLeaves = [...leaves];
    while (paddedLeaves.length < totalLeaves) {
      paddedLeaves.push(this.zeros[0]);
    }

    const tree: bigint[][] = [];
    tree[0] = paddedLeaves;

    for (let level = 1; level <= this.height; level++) {
      tree[level] = [];
      for (let i = 0; i < tree[level - 1].length; i += 2) {
        tree[level].push(this.hashPair(tree[level - 1][i], tree[level - 1][i + 1]));
      }
    }

    return tree;
  }

  public getRoot(): bigint {
    return this.tree[this.height][0];
  }

  public getProof(index: number): {
    proof: bigint[];
    pathIndices: number[];
  } {
    const proof: bigint[] = [];
    const pathIndices: number[] = [];

    let currentIndex = index;
    for (let i = 0; i < this.height; i++) {
      const levelSize = this.tree[i].length;
      const siblingIndex = currentIndex % 2 === 0 ? Math.min(currentIndex + 1, levelSize - 1) : currentIndex - 1;

      proof.push(this.tree[i][siblingIndex]);
      pathIndices.push(currentIndex % 2); // 0 for left, 1 for right

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { proof, pathIndices };
  }

  public static async verifyProof(
    leaf: bigint,
    proof: bigint[],
    pathIndices: number[],
    root: bigint,
  ): Promise<boolean> {
    const poseidon = await buildPoseidon();

    let currentHash = leaf;
    for (let i = 0; i < proof.length; i++) {
      const [left, right] = pathIndices[i] === 0 ? [currentHash, proof[i]] : [proof[i], currentHash];
      const hash = poseidon([left, right]);
      currentHash = poseidon.F.toObject(hash);
    }

    return currentHash === root;
  }
}

// Helper function to create a new Merkle Tree
export async function createMerkleTree(height: number, leaves: bigint[]): Promise<MerkleTree> {
  const poseidon = await buildPoseidon();
  return new MerkleTree(height, leaves, poseidon);
}

// Helper function to verify a proof
export async function verifyMerkleProof(
  leaf: bigint,
  proof: bigint[],
  pathIndices: number[],
  root: bigint,
): Promise<boolean> {
  return MerkleTree.verifyProof(leaf, proof, pathIndices, root);
}

/**
 * Calculates Poseidon hash of an arbitrary number of inputs
 * Mimics the behavior of PoseidonModular circuit
 * @param inputs Array of bigints to be hashed
 * @returns Promise<bigint> The final hash
 */
export async function poseidonModular(inputs: bigint[]): Promise<bigint> {
  const poseidon = await buildPoseidon();
  const CHUNK_SIZE = 16;

  // Calculate number of chunks
  const numElements = inputs.length;
  let chunks = Math.floor(numElements / CHUNK_SIZE);
  const lastChunkSize = numElements % CHUNK_SIZE;
  if (lastChunkSize !== 0) {
    chunks += 1;
  }

  let out: bigint | null = null;

  // Process each chunk
  for (let i = 0; i < chunks; i++) {
    const start = i * CHUNK_SIZE;
    let end = start + CHUNK_SIZE;
    let chunkHash: bigint;

    if (end > numElements) {
      // last chunk
      end = numElements;
      const lastChunk = inputs.slice(start, end);
      chunkHash = poseidon.F.toObject(poseidon(lastChunk));
    } else {
      const chunk = inputs.slice(start, end);
      chunkHash = poseidon.F.toObject(poseidon(chunk));
    }

    if (i === 0) {
      out = chunkHash;
    } else {
      out = poseidon.F.toObject(poseidon([out as bigint, chunkHash]));
    }
  }

  if (out === null) {
    throw new Error('No inputs provided');
  }

  return out;
}
