# Testarea la Protocoale Criptografice

A realizat: **Curmanschii Anton, IA1901**.


## 1. Protocoale de autentificare a utilizatorilor

> 1.1. Comparați la nivel de concept protocoalele de autentificare a utilizatorilor cu cele de autentificare a mesajelor.

Protocoalele de autentificare a utilizatorilor au ca scop demonstrarea de către o entitate A la o altă entitate B că A este de fapt A, iar nu un impostor ce pretinde să fie A. 
A ar dori să-și demonstreze identitatea pentru a obține acces la anumite resurse, valabile numai pentru utilizator autorizați.

Protocoalele de autentificare a mesajelor au ca scop demonstrarea originii mesajelor, a faptului că mesajul nu a fost preiat de un adversar, a faptului că mesajul nu a fost schimbat și asigură că expeditorul este acea entitate care a transmis mesajul (nerepudierea).


> 1.2. Descrieți protocolul interogare-răspuns de autentificare reciprocă bazat pe utilizarea unui număr aleator.

Următorul protocol este unul simplu și posibil.

$$ A \rightarrow B: {ID} _ A, R _ A, \\\\
B \rightarrow A: R _ B, E _ K(R _ A, {ID} _ B), \\\\
A \rightarrow B: E _ K(R _ B, {ID} _ A) $$

Unde $ {ID} _ A $ ($ {ID} _ B $) este numele sau identificatorul lui $ A (B) $, cunoscut de ambele părți, iar $ R _ A $ ($ R _ B $) este un număr aleator, generat de către $ A (B) $.


Pașii:

1. $ A $ generează $ R _ A $.
2. $ A $ transmite mesajul $ {ID} _ A, R _ A $ lui $ B $.
3. $ B $ calculează valoarea $ E _ K(R _ A, {ID} _ B) $.
2. $ B $ transmite mesajul $ R _ B, {ID} _ A, R _ A $ lui $ A $.
4. $ A $ calculează valoarea $ E _ K(R _ B, {ID} _ A) $ și o transmite lui B.


> 1.3. Descrieți pașii protocolului de autentificare unilaterală Fiat-Shamir. Menționați avantajul principal al schemei.

Fiat-Shamir este un protocol de autentificare băzat pe principiul dezvăluirii zero a secretului.
Prin urmare, utilizatorul care urmează a fi autentificat, nu împărțește informații despre secret cu verificatorul.

Notații:

- $ p, q $ perechea de numere prime RSA.
- $ n = pq $ este modulul după care se fac operațiile aritmetice.
- $ s $ este un număr secret deținut de demonstratorul identității sale $ A $, comprim cu $ n $.
- $ v = {mod}(s^2, n) $ este informația împărțită cu verificatorul.
- $ r $ este un număr aleator, $ r \in [1, n) $ (commitment).
- $ x = {mod}(r ^ 2, n) $ (probe).
- $ e \in \{0, 1\} $ este interogarea generată de către verificatorul $ B $.
- $ y $ este valoarea generată de către $ A $, luând în vedere valoarea $ e $.

Pașii:

1. A generează $ p, q, n, s $.
2. A calculează $ v $ și o pune în acces public.
3. Pentru $ N $ runde:
   * $ A $ generează $ r $ și $ x $.
   * $ A $ îl imparte pe $ x $ cu $ B $.
   * $ B $ trimite lui $ A $ o interogare $ e $.
   * $ A $ calculează $ y = r $ dacă $ e = 0 $ și $ y = mod(r, s) $ dacă $ e = 1 $.
   * $ A $ transmite $ y $ lui $ B $.
   * Dacă $ y = 0 $, $ B $ nu o acceptă.
   * Altfel, $ B $ verifică dacă $ mod(y ^ 2, n) = mod(x v ^ e, n) $. Dacă ele nu se coincid, $ B $ nu-l autentifică be $ A $.

Probabilitatea că $ A $ a ghicit corect în mod aleator la $ N $ runde, este aproape $ \frac { 1 } { 2 ^ N } $. 


> 1.4. Să considerăm următorul protocol de identificare reciprocă bazat pe un algoritm de criptare cu cheie simetrică $ K $, partajată de utilizatorii $ A $ și $ B $. 
> 
> 
> $$ A \rightarrow B: A, R _ A, \\\\
> B \rightarrow A: E _ K(R _ A), \\\\
> A \rightarrow B: E _ K(R _ A + 1) $$
> 
> Expuneți două modalități de atac asupra protocolului pe care 
> le poate efectua un adversar C  cu scopul de a se autentifica din numele utilizatorului A în fața lui B.

Copiez aici răspunsul din lucrul individual, deoarece întrebarea este aceeași.

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


## 2. Protocoale de autentificare a utilizatorilor

> 2.1. Formulați următoarele proprietăți  osibile ale protocoalelor de stabilire a cheii: prospețimea cheii, confirmarea cheii, 
> autentificarea implicită a cheii și autentificarea utilizatorului. Dați exemple de protocoale (de distribuire și de punere de acord) 
> ce nu satisfac nici una din aceste proprietăți, precum și exemple de protocoale ce satisfac toate proprietățile. 

*Prospețimea cheii* = garantia că cheia a fost generată recent, adică nu a fost folosită anterior.

*Confirmarea cheii* = $ A $ primește un fel de confirmare verificabilă matematic că $ B $ deține cheia de sesiune.

*Autentificarea implicită a cheii* = demonstrarea pentru $ A $ care obține cheia de sesiune că alte entități nu o dețin.

*Autentificarea utilizatorului* = demonstrarea identității unei entități $ A $ în fața unei alte entități $ B $.

Protocoale puternice ca Kerberos (distribuire), Station-to-Station (punere în acord) le satisfac pe toate.

> 2.2. Ce proprietăți suplimentare ale protocoalelor de stabilire a cheii satisface protocolul Shamir de stabilire a cheii de sesiune 
> fără a utiliza o cheie simetrică de lungă durată? 


- Protecția în fața adversarilor pasivi, deoarece fiecare parte generează nonce-ul din nou. 
- Clar că nu necesită o cheie prestabilită anterior, doar valoarea $ p $ trebuie să fie stabilită și împărțită.
- Nu asigură autentificarea utilizatorilor.
- Se poate folosi canale nesecurizate, deoarece singura cheie nu este transmisă explicit.


> 2.3. Pentru protocolul Shamir în calitate de parametri de intrare au fost selectate valorile  $ p = 7, a = 3, b = 4 $. 
> Determinați valorile ce sunt transmise în cele trei mesaje ale protocolului, dacă a fost selectată cheia de sesiune $ K = 4 $.

Verificăm valorile: 
- $ cmmdc(a, p - 1) = 1 $? $ cmmdc(3, 7 - 1) = cmmdc(3, 6) = 3 $, deci $ a $ nu poate fi utilizat drept parametru în protocol.
- Asemătător cu $ b $ (divizorul comun este $ 2 $). 

Vom modifica parametrii, să-i putem utiliza în protocol:

$ p = 17, a = 3, b = 5 $.

$ A $ calculează: $ mod(a ^ {-1}, p - 1) = mod(3 ^ {-1}, 16) = 11 $.

$ B $ calculează: $ mod(b ^ {-1}, p - 1) = mod(5 ^ {-1}, 16) = 13 $.

$ A \rightarrow B: mod(K ^ a, p) = mod(4 ^ {11}, 17) = 13 $.

$ B \rightarrow A: mod((K ^ a) ^ b, p) = mod(13 ^ {13}, 17) = 13 $.

$ A \rightarrow B: mod(K ^ b, p) = mod((K ^ {ab}) ^ { mod(a^{-1}, p - 1) }, p) = mod(13 ^ {11}, 17) = 4 $.

$ B $ calculează $ K = mod((K ^ {b}) ^ {mod(b^{-1}, p - 1)}, p) = mod(4 ^ {13}, 17) = 4 $.

> 2.4. Pentru protocolul MTI/A0 în calitate de parametri de intrare au fost selectate valorile $ p = 7, \alpha = 3, a = 2, b = 4 $.  
> Care este valoarea cheii de sesiune?

Verificăm parametrii:
- Oare $ \alpha = 3 $ este un generarol al grupului modulo $ p = 7 $? Da.


$ A $ calculează $ z _ A = mod({\alpha} ^ a, p) = mod(3 ^ 2, 7) = 2 $.

$ B $ calculează $ z _ B = mod({\alpha} ^ b, p) = mod(3 ^ 4, 7) = 4 $.

$ A $ selectează aleator un număr secret $ x $. Fie, $ x = 2 $.

$ B $ selectează aleator un număr secret $ y $. Fie, $ y = 3 $.
<!-- 
$ A \rightarrow B: x $.

$ B \rightarrow A: y $. -->

$ A \rightarrow B: mod({\alpha} ^ x, p) = mod(3 ^ 2, 7) = 2 $

$ A \rightarrow B: mod({\alpha} ^ y, p) = mod(3 ^ 3, 7) = 6 $ 

$ A $ calculează $ k = mod(({\alpha} ^ y) ^ a z_B ^ x, p) = mod(6 ^ 2 \times 4 ^ 2, 7) = 2 $.

$ B $ calculează $ k = mod(({\alpha} ^ x) ^ b z_A ^ y, p) = mod(2 ^ 4 \times 2 ^ 3, 7) = 2 $.

$ k = 2 $ este cheia de sesiune.