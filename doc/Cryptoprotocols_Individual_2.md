# Lucrul individual Nr.2 la Protocoale Criptografice

A realizat: **Curmanschii Anton, IA1901**.

Tema:  **Stabilirea cheilor**.

## Sarcinile

> 1) Pentru protocolul Shamir în calitate de parametri de intrare au fost selectate valorile $ p = 43, a = 17, b = 23 $. 
> Determinați valorile ce sunt transmise în cele trei mesaje ale protocolului, dacă a fost selectată cheia de sesiune $ K = 13 $.
>
> 2) Pentru  protocolul  Diffie-Hellman  în  calitate  de  parametri  de  intrare  au  fost  selectate  valorile
> $ p = 23, \alpha = 11, x = 3, y = 5 $. Determinați  valorile  ce  sunt  transmise  în  cele  două  mesaje  ale 
> protocolului. Care este valoarea cheii de sesiune?
>
> 3) Pentru protocolul MTI/A0 în calitate de parametri de intrare au fost selectate valorile $ p = 31, \alpha = 11, a = 25, b = 15 $.
> Care este valoarea cheii de sesiune?

## Realizarea

Am scris un program în D, vedeți [următorul link]().

## Executarea

```
$ dub --config=establish_key

Shamir
1st message A -> B: 24
2nd message B -> A: 17
3rd message A -> B: 40

Diffie-Hellman
1st message A -> B: 20
2nd message B -> A: 5
k = 10

MTI-A0
1st message A -> B: 29
2nd message B -> A: 6
k = 25
```