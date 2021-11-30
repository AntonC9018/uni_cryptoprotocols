# Lucrul individual la Protocoale Criptografice

A realizat: **Curmanschii Anton, IA1901**.

Tema:  **Autentificarea utilizatorilor**.

# Exercițiile

> 1. Pentru $ p = 569, q = 683, s = 157 $, efectuați pașii de la primele trei runde ale protocolului Fiat-Shamir.

Am realizat un program în D pentru aceasta.

```d
void main()
{
    import std.random : uniform;
    import std.stdio : writeln;
    import std.numeric : gcd;

    const ulong p = 569;
    const ulong q = 683;
    const ulong n = p * q;
    const ulong s = 157;

    // Se verifică dacă s este un secret valid (trebuie să fie coprim cu n).
    assert(gcd(s, n) == 1);

    // v is shared
    const ulong v = s^^2 % n;

    // t = numRound
    foreach (numRound; 0 .. 3)
    {
        // r = commitment
        // Se generează un număr aleator din intervalul [1, n)
        const r = uniform!("[)", ulong)(1, n); 
        // x = probe
        const x = r^^2 % n;
        // e = query    ori 0, ori 1
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
            // v^e este echivalent cu (v * e + 1 - e); 
            // Sau este 1 dacă e este 0 și 1 în alt caz.
            // Definițiile sunt echivalente, deoarece e este ori 0 ori 1.
            const rhs = x * (e == 1 ? v : 1) % n;

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
```


Executare:
```
t = 0
r = 68564
x = 189904
e = 1
y = 271619
y^2 mod n == xv^e mod n <==> 320108 == 320108

t = 1
r = 312345
x = 31453
e = 1
y = 71163
y^2 mod n == xv^e mod n <==> 362759 == 362759

t = 2
r = 107608
x = 340199
e = 0
y = 107608
y^2 mod n == xv^e mod n <==> 340199 == 340199
```


> 2. Pentru  protocolul  Fiat-Shamir, precizați care este probabilitatea ca un pretendent neonest să răspundă corect de 15 ori la interogările verificatorului.

Un pretendent neonest are probabilitatea de a ghici răspunsul corect de 50% de fiecare dată, deci răspunsul este $ \frac{1}{2^{15}} $.
De fapt, probabilitatea este mai mare cu o măsură nesemnificativă, deoarece el are șansă $ \frac{1}{n} $ de a ghici răspunsul, chiar dacă nu a ghicit corect acele 50%, dar această probabilitate este neglijabilă, deoarece $n$ este mare.


> 3. Să considerăm următorul protocol de identificare reciprocă bazat pe algoritm de criptare cu cheie simetrică $ K $, partajată de utilizatorii $ A $ și $ B $:
>
> $$ A \rightarrow B: A, R _ A, \\\\
> B \rightarrow A: R _ B, E _ K(R _ A), \\\\
> A \rightarrow B: E _ K(R _ B) $$
>
> Arătați că un adversar $ C $ poate efectueze un atac asupra protocolului și să se autentifice din numele 
> utilizatorului $ A $ în fața lui $ B $. Modificați protocolul astfel încât să se elimine vulnerabilitatea 
> menționată. 

Problema este că returnarea unui număr criptat direct de către $ B $ este o parte a protocolului.
Atacul din partea lui $ C $ se întâmplă astfel:

1. $ C $ inițiează o sesiune de autentificare cu utilizatorul $ B $, impersonându-l pe $ A $.
2. $ C $ transmite un oarecare număr $ a $ la $ B $, primind de la $ B $ un număr generat aleator $ b $, precum și versiunea lui criptată.
3. $ C $ deschide încă o sesiune cu $ B $, transmitându-i $ b $ ca numărul său generat aleator. $ C $ deja dispune de versiunea criptată acestui număr, pe care îl poate prezenta lui $ B $ la utlima etapă a protocolului inițial.

$ \text{Sesiunea} \space 1: \\\\
C \rightarrow B: A, a, \\\\
B \rightarrow C: b, E _ K ( a ) \\\\ \\\\
\ldots \\\\
\text{Sesiunea} \space 2: \\\\
C \rightarrow B: A, b, \\\\
B \rightarrow C: R _ B, E _ K ( b ) \\\\
\ldots \\\\
\text{Sesiunea} \space 1: \\\\
C \rightarrow B: E _ K ( b ) $

O soluție simplă este de stabilit că trebuie să fie criptat identificatorul concatenat cu numărul aleator.
Însă este important ca el să nu fie combinat cu numărul aleator simplu cu $ \oplus $, deoarece adversarul ar putea calcula numărul aleator corespunzător care ar anula acest factor. Deci în cazul în care protocolul este augmentat la:

$ A \rightarrow B: A, R _ A, \\\\
B \rightarrow A: R _ B, E _ K(A \oplus R _ A), \\\\
A \rightarrow B: E _ K(B \oplus R _ B) $

Atunci algoritmul rămâne vulnerabil, deoarece:

$ \text{Sesiunea} \space 1: \\\\
C \rightarrow B: A, a, \\\\
B \rightarrow C: b, E _ K ( A \oplus a ) \\\\ \\\\
\ldots \\\\
\text{Sesiunea} \space 2: \\\\
c = b \oplus A \oplus B \\\\
C \rightarrow B: A, c \\\\
B \rightarrow C: R _ B, E _ K ( A \oplus c ) \\\\
E_K(A \oplus c) = E_K(A \oplus b \oplus A \oplus B) = E_K(B \oplus b) \\\\
\ldots \\\\
\text{Sesiunea} \space 1: \\\\
C \rightarrow B: E_K(B \oplus b) $

Dacă cerem $ E_K(A || R_A) $ în algoritm, atunci deja posibilitatea dată se elimină.

> 4. Să considerăm următorul protocol de identificare reciprocă bazat pe un algoritm de criptare cu cheie simetrică $ K $, partajată de utilizatorii $ A $ și $ B $:
> 
> $$ A \rightarrow B: A, R _ A, \\\\
> B \rightarrow A: E _ K(R _ A), \\\\
> A \rightarrow B: E _ K(R _ A + 1) $$
> 
> Expuneți două modalități de atac asupra protocolului pe care le poate efectua un adversar $ C $ cu 
> scopul de a se autentifica din numele utilizatorului $ A $ în fața lui $ B $.


Cea mai simplă idee ar fi să selectăm a doua oară un număr $ R_A $ mai mare ca cel precedent cu o unitate. Deci: 

$ \text{Sesiunea} \space 1: \\\\
C \rightarrow B: A, a, \\\\
B \rightarrow C: E _ K ( a ) \\\\ \\\\
\ldots \\\\
\text{Sesiunea} \space 2: \\\\
C \rightarrow B: A, a + 1, \\\\
B \rightarrow C: E _ K ( a + 1 ) \\\\
\ldots \\\\
\text{Sesiunea} \space 1: \\\\
C \rightarrow B: E _ K ( a + 1 ) $

Sau poate termina a doua sesiune în loc de a prima, utilizând datele primite la a prima sesiune:

$ \text{Sesiunea} \space 1: \\\\
C \rightarrow B: A, a, \\\\
B \rightarrow C: E _ K ( a ) \\\\ \\\\
\ldots \\\\
\text{Sesiunea} \space 2: \\\\
C \rightarrow B: A, a - 1, \\\\
B \rightarrow C: E _ K ( a - 1 ) \\\\
C \rightarrow B: E _ K ( a ) $

> 5. Explicați cum realizează autentificarea utilizatorilor sistemul de operare Windows.

Fiecare utilizator poate avea o parolă obișnuită; se mai poate seta autentificarea pe mai mulți factori cu parole one-time sau autentificarea biometrică. La logare, utilizatorul va fi rugat să introducă parola. Fără parola, nu poate intra în profilul său.

Cum Windows stochează parola eu nu am studiat, dar am citit pe internet că Windows serveri folosesc protocolul Kerberos pentru aceasta.
