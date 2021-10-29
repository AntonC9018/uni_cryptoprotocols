module common.util;

import std.range;
import std.string;
import std.algorithm;

auto fromHexString(string source)
{
    import std.utf;
    import std.conv : to;
    return source.byCodeUnit.chunks(2).map!(c => c.to!ubyte(16));
}
unittest
{
    assert(equal(fromHexString("1234ABcd"), [0x12, 0x34, 0xab, 0xcd]));
}

void fromHexString(ubyte[] output, string source)
{
    assert(output.length == source.length / 2);
    foreach (i, b; fromHexString(source).enumerate)
        output[i] = b;
}