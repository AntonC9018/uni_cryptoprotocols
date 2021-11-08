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

int ceilingDivide(int a, int b)
{
    return (a + b - 1) / b;
}
unittest
{
    assert(ceilingDivide(1, 2) == 1);
}

uint endianSwap(uint a)
{
    return ((a >> 24) & 0x000000ff) 
        | ((a >> 8) & 0x0000ff00)
        | ((a << 8) & 0x00ff0000)
        | ((a << 24) & 0xff000000); 
}
unittest
{
    // assert(endianSwap(0x00000080) == int.min);
    assert(endianSwap(0x12345678) == 0x78563412);
}

uint maybeEndianSwap(uint a)
{
    import std.system;
    static if (endian == Endian.bigEndian)
        return endianSwap(a);
    else return a;
}

void maybeEndianSwap(uint[] bytesAsInts)
{
    import std.system;
    static if (endian == Endian.bigEndian)
    foreach (ref _uint; bytesAsInts)
        _unit = endianSwap(_uint);
}

bool isPowerOfTwo(ulong number)
{
    size_t index = 0;
    while (index < 64)
        if ((number >> index++) & 1)
            break;
    while (index < 64)
        if ((number >> index++) & 1)
            return false;
    return true;
}

int intLog2(ulong number)
{
    int index = 63;
    while (index >= 0)
    {
        if ((number >> index) & 1)
            return index;
        index--;
    }
    return int.min;
}

template Resize(NestedArrayType, size_t byFactor)
{
    import std.traits;
    static assert(NestedArrayType.length % byFactor == 0);
    size_t newLength = NestedArrayType.length / byFactor;
    alias ArrayType = ElementType!NestedArrayType;
    alias NewArrayType = ElementType!ArrayType[ArrayType.length * byFactor];
    alias Resize = NewArrayType[NestedArrayType.length / byFactor]; 
}

auto resize(size_t byFactor, TNestedArray)(inout TNestedArray array)
{
    return cast(Resize!(TNestedArray, byFactor)) array;
}