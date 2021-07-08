erltss2
=====
An OTP NIF library wrapper around tpm2-tss.
https://github.com/tpm2-software/tpm2-tss

Build
-----

    $ make

Use
---

You will need a TPM2 chip attached to the system and installed tpm2-tss. 
You also might want to install tpm2-abrmd if your kernel doesn't support Resource Manager.

For development purposes you can then clone this repository, and start
an Erlang shell to communicate with the TPM:

    $ git clone https://github.com/openEPC/erltss2
    $ cd erltss2
    $ ./rebar3 shell
    $ erlfapi:fapi_Initialize(null).

Then checkout TCG Feature API (FAPI) specification for commands parameters. 
It is also hady too look into tpm2-tools man pages.