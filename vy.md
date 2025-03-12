# Lagrange coeficient in CGGMP21
(for threshold signing)

## Source code
* cggmp21-spec.pdf (page 20/step 1)
* cggmp21/src/signing.rs (line 555)
* cggmp21-keygen/src/threshold.rs (line 450)
* key-share/src/lib.rs (line 255)

## Why Lagrange coeficient in CGGMP21
* In threshold secret sharing (Sharmir/VSS), a secret $S$ is splited into many shares. Each share is a point in a $(t-1)$-degree polynomial $P(x)$ - which has the free coeffiecient $a_0 = S$. Any group of at least $t$ shares can recover the secret using Lagrange interpolation.
* However, in signing phase, we need to convert VSS shares into additive shares. For example, we have $k$ ($k >= t$) VSS shares $(x_1, x_2, ... x_{k})$ from secret $S$. Then, the additive shares will be $(x'_1, x'_2, ... x'_{k})$, where $\displaystyle\sum_{i=1}^{k}x'_i = S$. CGGMP21 uses Lagrange coeficient.

## What is Lagrange interpolation?
> Read in notebook (Xi Trum)

## What is Lagrange coefficient?
> Read in notebook (Xi Trum)
