module lamport;

import std.range;
import std.algorithm;
import std.random;
import std.string;
import std.stdio;
import std.traits;
import std.digest.sha;
import common.util;


/// https://www.wikiwand.com/en/Lamport_signature
alias LamportKey = ulong[4][2][256];
alias LamportSignature = ulong[4][256];

LamportKey generateLamportPrivateKey()
{
    LamportKey result;
    foreach (ref ulong value; cast(ulong[]) result[])
        value = uniform!ulong;
    return result;
}

template Lamport(alias hashFunction)
{
    alias generatePrivateKey = generateLamportPrivateKey;

    LamportKey generatePublicKey(in LamportKey privateKey)
    {
        LamportKey result;
        foreach (index, value; cast(const ulong[4][]) privateKey)
            (cast(ulong[4][]) result)[index] = cast(ulong[4]) hashFunction(cast(ubyte[]) value[]);
        return result;
    }

    LamportSignature generateSignature(const ubyte[] message, in LamportKey key)
    {
        auto messageHash = cast(ulong[4]) hashFunction(message);

        LamportSignature result;

        foreach (byteIndex; 0..4)
        foreach (bitIndex; 0..64)
        {
            size_t index = byteIndex * 64 + bitIndex;
            result[index] = key[index][(messageHash[byteIndex] >> bitIndex) & 1];
        }

        return result;
    }

    bool validateSignature(const ubyte[] message, in LamportSignature signature, in LamportKey publicKey)
    {
        auto messageHash = cast(ulong[4]) hashFunction(message);

        foreach (byteIndex; 0..4)
        foreach (bitIndex; 0..64)
        {
            size_t index = byteIndex * 64 + bitIndex;
            auto hash = cast(ulong[4]) hashFunction(cast(ubyte[]) signature[index]);
            if (hash != publicKey[index][(messageHash[byteIndex] >> bitIndex) & 1])
                return false;
        }
        return true;
    }

    struct MerkleySigningContext(size_t numMessages)
    {
        LamportKey[numMessages] _privateKeys;
        LamportKey[numMessages] _publicKeys;
        MerkleTree!(MerkleNodesToLevels!numMessages, hashFunction) _merkleTree;
        size_t currentIndex;

        bool isUsable() { return currentIndex < numMessages; }
        void refresh()
        {
            foreach (ref key; _privateKeys)
                key = generatePrivateKey();
            foreach (index, ref key; _publicKeys)
                key = generatePublicKey(_privateKeys[index]);
            _merkleTree.initialize(_publicKeys);
            currentIndex = 0;
        }

        ulong[4] getPublicKey()
        {
            return cast(ulong[4]) _merkleTree.getLevel(_merkleTree.numLevels - 1)[0];
        }

        auto _getNextSignature(const ubyte[] message) in(isUsable)
        {
            LamportMerkleSignature!(_merkleTree.numLevels - 1) result = void;
            result.publicKey = _publicKeys[currentIndex];
            result.signature = generateSignature(message, _privateKeys[currentIndex]);
            result.auths     = cast(ulong[4][_merkleTree.numLevels - 1]) _merkleTree.getIntermediateAuthSteps(currentIndex);
            currentIndex++;
            return result;
        }

        auto getNextSignature(const ubyte[] message)
        {
            if (!isUsable)
                refresh();
            return _getNextSignature(message);
        }
    }

    MerkleySigningContext!numMessages* merkleySigningContext(size_t numMessages)()
    {
        auto result = new MerkleySigningContext!numMessages();
        result.refresh();
        return result;
    }

    // struct MerkleyValidationContext(size_t numMessages)
    // {
    //     enum numAuths = MerkleNodesToLevels!numMessages - 1;
    //     ulong[4] publicKey;


    // }

    bool validateMerkleSignature(TSignature : LamportMerkleSignature!numAuths, size_t numAuths)
        (in TSignature merkleSignature, size_t messageIndexInBatch, in ulong[4] merkleTreeRoot)
    {
        alias Info = MerkleTreeInfo!(numAuths + 1, hashFunction);

        auto currentHash      = hashFunction(cast(ubyte[]) merkleSignature.publicKey);
        auto nodeIndexAtLevel = messageIndexInBatch;

        foreach (levelIndex; 0..numAuths)
        {
            Info.THash[2] buffer = void;
            size_t actualIndex = nodeIndexAtLevel + Info.nodeOffsetAtLevel[levelIndex];
            buffer[ actualIndex & 1] = currentHash;
            buffer[~actualIndex & 1] = cast(Info.THash) merkleSignature.auths[levelIndex];
            currentHash = hashFunction(buffer);
            nodeIndexAtLevel /= 2;
        }
        return cast(ulong[4]) currentHash == merkleTreeRoot;
    }

    // bool validateMerkleSignature(in DynamicLamportMerkleSignature merkleSignature, size_t messageIndexInBatch, in ulong[4] merkleTreeRoot)
    // {
    //     alias Info = MerkleTreeInfo!(numAuths + 1, hashFunction);
    //     auto publicKeyHash    = hashFunction(cast(ubyte[]) merkleSignature.publicKey);
    //     auto nodeIndexAtLevel = messageIndexInBatch;
    //     auto currentHash      = publicKeyHash;
        
    //     foreach (const auth; merkleSignature.auths)
    //     {
    //         Info.THash[2] buffer = void;
    //         size_t actualIndex = nodeIndexAtLevel + Info.nodeOffsetAtLevel[levelIndex];
    //         buffer[ actualIndex & 1] = currentHash;
    //         buffer[~actualIndex & 1] = cast(Info.THash) auth;
    //         currentHash = hashFunction(buffer);
    //         nodeIndexAtLevel /= 2;
    //     }
    //     return cast(ulong[4]) currentHash == merkleTreeRoot;
    // }
}
unittest
{
    alias Lamp = Lamport!sha256Of;
    auto privateKey = Lamp.generatePrivateKey();
    auto publicKey = Lamp.generatePublicKey(privateKey);
    auto signature = Lamp.generateSignature([1, 2, 3], privateKey);
    assert(Lamp.validateSignature([1, 2, 3], signature, publicKey));
    auto signature2 = Lamp.generateSignature([3, 2, 1], privateKey);
    assert(signature != signature2);
}
unittest
{
    alias Lamp = Lamport!sha256Of;
    ubyte[][32] messages = "1234567890qwertyuiopasdfghjklzxc".representation.dup;
    auto signingContext = Lamp.merkleySigningContext!(messages.length);
    auto rootHash = signingContext.getPublicKey();
    foreach (index, message; messages)
    {
        auto signature = signingContext.getNextSignature(message);
        assert(signature.publicKey == Lamp.generatePublicKey(signingContext._privateKeys[index]));
        assert(Lamp.validateMerkleSignature(signature, index, rootHash));
        assert(Lamp.validateSignature(message, signature.signature, signature.publicKey));
    }
    assert(!signingContext.isUsable);
}

struct LamportMerkleSignature(size_t numAuths)
{
    LamportSignature signature;
    LamportKey publicKey;
    ulong[4][numAuths] auths;
}

struct DynamicLamportMerkleSignature
{
    LamportSignature signature;
    LamportKey publicKey;
    ulong[4][] auths;
}

/// https://www.wikiwand.com/en/Merkle_signature_scheme#/Signature_generation
auto getIntermediateAuthSteps(MerkleTreeType)(in MerkleTreeType merkleTree, in size_t indexOfUsedKey) 
    in (indexOfUsedKey < 2 ^^ (MerkleTreeType.numLevels - 1))
{
    MerkleTreeType.THash[MerkleTreeType.numLevels - 1] result;
    size_t knownHashIndex = indexOfUsedKey;

    foreach (levelIndex; 0..MerkleTreeType.numLevels - 1)
    {
        size_t authIndex = knownHashIndex ^ (cast(size_t) 1);
        result[levelIndex] = merkleTree.getLevel(levelIndex)[authIndex];
        knownHashIndex /= 2;
    }

    return result;
}

template MerkleTreeInfo(size_t _numLevels, alias hashFunction)
{
    enum length = 2^^numLevels - 1;
    enum numLevels = _numLevels;
    alias THash = typeof(hashFunction([1, 2, 3]));

    static size_t getLevelLength(size_t index)
    {
        return 2 ^^ (numLevels - index - 1);
    }

    static private size_t[numLevels] getNodeOffsetsAtLevel()
    {
        size_t[numLevels] result;
        result[0] = 0;
        foreach (i; 0 .. numLevels - 1)
            result[i + 1] = result[i] + getLevelLength(i);
        return result;
    }
    enum size_t[numLevels] nodeOffsetAtLevel = getNodeOffsetsAtLevel();
}


/// https://www.wikiwand.com/en/Merkle_signature_scheme
struct MerkleTree(size_t _numLevels, alias hashFunction)
{
    mixin MerkleTreeInfo!(_numLevels, hashFunction);
    
    THash[length] nodes;

    inout(THash)[] getLevel(size_t index) inout
        in (index <= numLevels)
    {
        size_t offset = nodeOffsetAtLevel[index];
        size_t levelLength = getLevelLength(index);
        return nodes[offset .. offset + levelLength];
    }

    enum level0Length = getLevelLength(0);
    void initialize(TItems : T[level0Length], T)(in TItems items)
    {
        foreach (i, const element; items)
            this.nodes[i] = hashFunction(cast(ubyte[]) element);

        size_t previousOffset = 0;
        size_t currentOffset = items.length;
        size_t currentLength = items.length / 2;

        while (currentLength > 0)
        {
            foreach (i; 0..currentLength)
            {
                size_t index = i + currentOffset;
                assert(this.length > index);
                size_t prevLevelIndex = i * 2 + previousOffset;
                this.nodes[index] = hashFunction(this.nodes[prevLevelIndex .. prevLevelIndex + 2]);
            }
            previousOffset = currentOffset;
            currentOffset += currentLength;
            currentLength /= 2;
        }

        assert(currentOffset == this.length);
    }
}

template MerkleNodesToLevels(size_t numNodes)
{
    static assert(numNodes > 0 && isPowerOfTwo(numNodes));
    enum MerkleNodesToLevels = intLog2(numNodes) + 1;
}

template merkleTree(size_t numNodes, alias hashFunction)
{
    alias ResultType = MerkleTree!(MerkleNodesToLevels!numNodes, hashFunction);

    auto merkleTree(T)(in T[ResultType.length] items)
    {
        ResultType result;
        result.initialize(items);
        return result;
    }
}