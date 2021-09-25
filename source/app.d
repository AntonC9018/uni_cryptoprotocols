import std.digest;
import std.digest.sha;
import std.range;
import std.string;

void main()
{
}

ubyte[] calculateHMAC(alias hashFunction, int blockSize)(const(ubyte)[] key, const(ubyte)[] message)
{
    if (key.length > blockSize)
    {
        auto key0 = hashFunction(key);
        key = key0;
    }
    key.length = blockSize;
    
    ubyte[blockSize] outerPad = void;
    outerPad[] = key[] ^ 0x5c;
    ubyte[blockSize] innerPad = void;
    innerPad[] = key[] ^ 0x36;

    return hashFunction(outerPad ~ hashFunction(innerPad ~ message)).dup;
}
unittest
{
    auto key = representation("key");
    auto message = representation("The quick brown fox jumps over the lazy dog");
    auto hmac = calculateHMAC!(sha256Of, 64)(key, message);
    assert(hmac.toHexString!(LetterCase.lower) == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}