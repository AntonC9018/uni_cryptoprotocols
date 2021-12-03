void main()
{
    writeln("Shamir");
    shamir();
    
    writeln("\nDiffie-Hellman");
    diffieHellman();

    writeln("\nMTI-A0");
    mtia0();
}

import std.stdio;
import std.math : powmod;
import std.stdio : writeln;
import std.numeric : lcm, gcd;


// Simplest algo that checks all numbers until an inverse is found.
// a must be coprime wrt n.
ulong inverseModulo(ulong a, ulong n)
{
    // This simple form only works for prime n's
    // return powmod(a, n - 2, n);

    ulong b = 2;
    while (b < n)
    {
        if (((a * b) % n) == 1)
            return b;
        b++;
    }
    assert(0);
}

void shamir()
{
    ulong p = 43;
    ulong a = 17;
    ulong b = 23;

    assert(gcd(a, p - 1) == 1);
    assert(gcd(b, p - 1) == 1);

    ulong inverseA = inverseModulo(a, p - 1);
    ulong inverseB = inverseModulo(b, p - 1);
    
    ulong K = 13;
    
    ulong message1 = powmod(K, a, p);
    writeln("1st message A -> B: ", message1);

    ulong message2 = powmod(message1, b, p);
    writeln("2nd message B -> A: ", message2);

    ulong message3 = powmod(message2, inverseA, p);
    writeln("3rd message A -> B: ", message3);

    ulong calculatedK = powmod(message3, inverseB, p);
    assert(K == calculatedK);
}

void diffieHellman()
{
    ulong p = 23;
    ulong alpha = 11;
    ulong x = 3;
    ulong y = 5;

    assert(gcd(alpha, p) == 1);

    ulong message1 = powmod(alpha, x, p);
    writeln("1st message A -> B: ", message1);

    ulong message2 = powmod(alpha, y, p);
    writeln("2nd message B -> A: ", message2);

    ulong k_A = powmod(message2, x, p);
    ulong k_B = powmod(message1, y, p);
    
    writeln("k = ", k_A);
    // writeln("k = ", k_B);
    assert(k_A == k_B);
}


void mtia0()
{
    ulong p = 31;
    ulong alpha = 11;
    ulong a = 25;
    ulong b = 15; 
    ulong x = 3;
    ulong y = 5;

    assert(gcd(alpha, p) == 1);

    ulong z_A = powmod(alpha, a, p); 
    ulong z_B = powmod(alpha, b, p); 

    ulong message1 = powmod(alpha, x, p);
    writeln("1st message A -> B: ", message1);

    ulong message2 = powmod(alpha, y, p);
    writeln("2nd message B -> A: ", message2);

    ulong k_A = (powmod(message2, a, p) * powmod(z_B, x, p)) % p;
    ulong k_B = (powmod(message1, b, p) * powmod(z_A, y, p)) % p;
    
    writeln("k = ", k_A);
    // writeln("k = ", k_B);
    assert(k_A == k_B);
}
