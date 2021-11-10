module skid;

import std.range;
import std.algorithm;
import std.random;
import std.string;
import std.stdio;
import std.digest.sha;
import common.util;


/// https://people.cs.rutgers.edu/~pxk/rutgers/notes/content/13-crypto.pdf#page=10&zoom=auto,-151,380

struct SKID(TDigest, TEncryptionBlockCipher)
{
    TDigest _digest;
    TEncryptionBlockCipher _blockCipher;
    /// Step 1: generate a random number
    /// I don't know if this needs to be encrypted?
    ulong _ownRandomNumber;
    const(ubyte)[] _ownName;

    static assert(__traits(compiles, _blockCipher.encrypt(_digest.finish())), 
        "The block sizes of the hash and the block cipher need to match");

    void resetRandomNumber(ulong number)
    {
        _ownRandomNumber = number;
    }

    auto encryptHash() { return _blockCipher.encrypt(_digest.finish()); }
    
    /// Step 2: create authentication hash.
    auto computeHashA(ulong receivedRandomNumber)
    {
        _digest.put(receivedRandomNumber.bytes);
        _digest.put(_ownRandomNumber.bytes);
        _digest.put(_ownName);
        return encryptHash();
    }

    /// Step 3: check authentication hash.
    bool validateHashA(in typeof(_digest.finish()) encryptedHash, ulong receivedRandomNumber, const ubyte[] expectedName)
    {
        _digest.put(_ownRandomNumber.bytes);
        _digest.put(receivedRandomNumber.bytes);
        _digest.put(expectedName);
        return encryptedHash == encryptHash();
    }

    /// Step 4: compute hash of the random number and own identity.
    auto computeHashB(ulong receivedRandomNumber)
    {
        _digest.put(receivedRandomNumber.bytes);
        _digest.put(_ownName);
        return encryptHash();
    }

    /// Step 5: validate hash of the other party.
    bool validateHashB(in typeof(_digest.finish()) encryptedHash, const ubyte[] expectedName)
    {
        _digest.put(_ownRandomNumber.bytes);
        _digest.put(expectedName);
        return encryptedHash == encryptHash();
    }
}

auto skid(TDigest, TEncryptionBlockCipher)(TDigest digest, TEncryptionBlockCipher cipher, string name)
{
    return SKID!(TDigest, TEncryptionBlockCipher)(digest, cipher, 0, name.representation);
}

import common.aes;
import std.digest.md;

struct AESWrapper
{
	AESContext!(Yes.encrypt) encryptionContext;
	auto encrypt(in ubyte[16] bytes) { return cryptEcb(encryptionContext, bytes); }
}
unittest
{
    const(ubyte)[16] key = "1234567890asdfgh".representation.dup;
    
    auto Alice = skid(MD5(), AESWrapper(createEncryptionContext(key)), "Alice");
    auto Bob   = skid(MD5(), AESWrapper(createEncryptionContext(key)), "Bob");

    auto alicesRandomNumber = uniform!ulong;
    Alice.resetRandomNumber(alicesRandomNumber);
    
    auto bobsRandomNumber = uniform!ulong;
    Bob.resetRandomNumber(bobsRandomNumber);

    // Both parties receive each other's random numbers
    // Alice will validate Bob's identity first.
    auto hash1 = Bob.computeHashA(alicesRandomNumber);
    assert(Alice.validateHashA(hash1, bobsRandomNumber, "Bob".representation));

    auto hash2 = Alice.computeHashB(bobsRandomNumber);
    assert(Bob.validateHashB(hash2, "Alice".representation));
}