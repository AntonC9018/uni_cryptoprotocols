
void main()
{
    // import std.math : ;
    import std.random : uniform;
    import std.stdio : writeln;
    import std.numeric : gcd;

    const ulong p = 569;
    const ulong q = 683;
    const ulong n = p * q;
    const ulong s = 157;

    assert(gcd(s, n) == 1);

    // v is shared
    const ulong v = s^^2 % n;

    // t = numRound
    foreach (numRound; 0 .. 3)
    {
        // r = commitment
        const r = uniform!("[)", ulong)(1, n);
        // x = probe
        const x = r^^2 % n;
        // e = query    either 0 or 1
        const e = uniform!ulong & 1;

        // y = answer
        const y = {
            if (e == 0)
                return r;
            else // if (e == 1)
                return (r * s) % n;
        }();

        if (y == 0)
        {
            writeln("Proof not accepted because y was 0.");
            return;
        }

        {
            const lhs = y^^2 % n;
            const rhs = x * (v * e + 1 - e) % n;

            writeln(
                "\nt = ", numRound,
                "\nr = ", r, 
                "\nx = ", x, 
                "\ne = ", e, 
                "\ny = ", y, 
                "\ny^2 mod n == xv^e mod n <==> ", lhs, " == ", rhs);

            if (lhs != rhs)
            {
                writeln("Proof failed verification.");
                return;
            }
        }
    }
}