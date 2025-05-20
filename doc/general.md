# Blinded Musig2

## Abstract
Based on the Musig2 signature scheme, we add blinding factors to the scheme in
order to have the signers learn nothing about what they are signing and who is
participating in the session.

## Introduction
In order to facilitate the signing session, we introduce a coordinator. Note
that the coordinator learns everything going on in the session, like what is
being signed, who is participating and all blinding factors being used. The
coordinator does not have the ability to fake signatures without involving the
signers, however, since only the quorum of signers can create valid signatures
for the aggregate public key.

# Blinded multi-signature protocol

### Notes on blinded MuSig in the general setting 
An open reserch question is whether blinded MuSig1 and MuSig2 can be secure in
a concurrent setting, where a signer potentially can sign multiple messages in
parallel using the same key [wagner attack, citation].

In non-blinded Musig2, Wagner's attack is avoided by having the final signing
nonce be a non-linear combination of the signers' individual nonces. Since the
signers' cannot inspect the final nonce and message when blinded, they have no
way to verify that they are not signing for a nonce that has been tampered
with.

However, in our setup the coordinator is the trusted orchestrator, and can do
this verification. The coordinator is therefore the only one that can perform
such an attack, and one should be aware of this security model when using the
scheme.

##  Blinded MuSig2 signing
We'll have two signers take part, but it could easily be generalized to more
signers.

The coordinator asks the signers for keys and nonces.

The signers choose two nonces each 

$$
\begin{aligned}
R^1_A = r^1_A * G  \\
R^2_A = r^2_A * G 
\end{aligned}
$$

and

$$
\begin{aligned}
R^1_B = r^1_B * G \\
R^2_B = r^2_B * G 
\end{aligned}
$$

Public keys are $X_A = x_A * G$ and $X_B = x_B * G$.

The coordinator uses all the signers' public values to generate the MuSig2
factors that each signer would create in the regular MuSig2 protocol:

$$
\begin{aligned}
l = H(X_A|X_B) \\
c_A = H(l|X_A) \\
c_B = H(l|X_B) \\
X'_A = c_A * X_A \\
X'_B = c_B * X_B \\
\end{aligned}
$$

Aggregate nonces:

$$
\begin{aligned}
R^1 = R^1_A + R^1_B \\
R^2 = R^2_A + R^2_B \\
\end{aligned}
$$

Aggregate public key: 

$$
X' = X'_A + X'_B
$$


Nonce blinder:

$$
\begin{aligned}
b = H(R^1|R^2|X'|m) \\
\end{aligned}
$$


Final nonce:

$$
R = R^1 + b * R^2 \\
$$

Coordinator generates blinding values $\alpha_A, \beta_A, \alpha_B, \beta_B, \gamma_A, \gamma_B$, and
calculates blinded signing nonce:

$$
R' = R + (\gamma_A * R^2_A) + (\gamma_B * R^2_B) + (\beta_A * c_A * X_A) + (\beta_B * c_B * X_B) + (\alpha_A + \alpha_B) * G \\
$$

The coordinator constructs $e$ for signing, where $m$ is the message to sign.

$$
e = H(R', X', m)
$$

The coordinator now blinds the message for each signer, to ensure they don't
learn anything about what they are signing.

$e_A = e + \beta_A$ and $e_B = e + \beta_B$.

$b_A = b + \gamma_A$ and $b_B = b + \gamma_B$.

$e'_A = e_A * c_A$ and $b_A$ is sent to Alice.

$e'_B = e_B * c_B$ and $b_B$ is sent to Bob.

The signers can now sign:

$$
\begin{aligned}
s'_A &= r^1_A + b_A * r^2_A + e'_A * x_A \\
    &= r^1_A + (b + \gamma_A) * r^2_A + e * c_A * x_A + \beta_A * c_A * x_A\\
s'_B &= r^1_B + b_B * r^2_B + e'_B * x_B \\
    &= r^1_B + (b + \gamma_B) * r^2_B + e * c_B * x_B + \beta_B * c_B * x_B\\
\end{aligned}
$$

coordinator unblinds every partial signature:

$$
\begin{aligned}
s_A = s'_A + \alpha_A \\
s_B = s'_B + \alpha_B
\end{aligned}
$$

Aggregate signature:

$$
\begin{aligned}
s   &= s_A + s_B \\
s   &= s'_A + \alpha_A + s'_B + \alpha_B \\
    &= r^1_A + (b + \gamma_A) * r^2_A + e * c_A * x_A + \beta_A * c_A * x_A + \alpha_A \\
    &+ r^1_B + (b + \gamma_B) * r^2_B + e * c_B * x_B + \beta_B * c_B * x_B + \alpha_B \\
    &= (r^1_A + r^1_B) + b * (r^2_A + r^2_B) + (\gamma_A * r^2_A) + (\gamma_B * r^2_B) \\
    &+ e * (c_A * x_A + c_B * x_B)  + \beta_A * c_A * x_A + \beta_B * c_B * x_B + (\alpha_A + \alpha_B) \\
\end{aligned}
$$

Signature check:

$$
\begin{aligned}
s*G &= (r^1_A + r^1_B) * G + b * (r^2_A + r^2_B) * G + (\gamma_A * r^2_A) * G + (\gamma_2 * r^2_B) * G \\
    &+ e * (c_A * x_A + c_B * x_B) * G + \beta_A * c_A * x_A * G + \beta_B * c_B * x_B * G + (\alpha_A + \alpha_B) * G\\
    &= (R^1_A + R^1_B) + b * (R^2_A + R^2_B) + (\gamma_A * R^2_A) + (\gamma_B * R^2_B) \\
    &+ e * (c_A * X_A + c_B * X_B) + (\beta_A * c_A * X_A) + (\beta_B * c_B * X_B) + (\alpha_A + \alpha_B) * G\\
    &= R + (\gamma_A * R^2_A) + (\gamma_B * R^2_B) + (\beta_A * c_A * X_A) + (\beta_B * c_B * X_B) + (\alpha_A + \alpha_B) * G + e * (X'_A + X'_B)  \\
    &= R' + e * X' \\
\end{aligned}
$$

making $(R', s)$ a valid signature for message $m$ using aggregate key $X'$.
