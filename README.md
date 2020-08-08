### kutil

----

*kutil* is a command line utility to work with Kerberos ticket cache files (MIT format).
It supports different operations like merging, splitting and modifying ticket caches.
A detailed list of all supported operations can be found in the [operations section](#supported-operations).

![](https://github.com/qtc-de/kutil/workflows/master%20Python%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/kutil/workflows/develop%20Python%20CI/badge.svg?branch=develop)


### Table of Contents

----

- [Installation](#installation)
- [Supported Operations](#supported-operations)
  * [Credential Modifications](#credential-modifications) 
    + [Change Principal](#change-principal)
    + [Change Realm](#change-realm)
    + [Change Service](#change-service)
    + [Change SPN](#change-spn)
    + [Change Target](#change-Target)
  * [Ticket Cache Modifications](#ticket-cache-modifications)
    + [Clear Duplicates](#clear-duplicates)
    + [Change Default Principal](#change-default-principal)
    + [Delete Credential](#delete-credential)
    + [Merge Ticket Caches](#merge-ticket-caches)
    + [Split Ticket Caches](#split-ticket-caches)
  * [Miscellaneous](#miscellaneous)
    + [Decrypt Credential](#decrypt-credential)
    + [Hash Password](#hash-password)
    + [List Ticket Cache](#list-ticket-cache)
- [Why Modifying Tickets](#why-modifying-tickets)
- [Modifying Encrypted Ticket Content](#modifying-encrypted-ticket-content)
- [Acknowledgements](#acknowledgements)


### Installation

----

*kutil* can be build and installed as a *pip* package. The following
command installs *kutil* for your current user profile:

```console
$ pip3 install kutil
```

You can also build *kutil* from source and install it directly by using
the following commands:

```console
$ git clone https://github.com/qtc-de/kutil
$ cd kutil
$ pip3 install -r requirements.txt
$ python3 setup.py sdist
$ pip3 install dist/*
```

Additionally, *kutil* ships a [bash-completion](./kutil/resources/bash_completion.d/kutil) script.
The completion script is installed automatically, but relies on the [completion-helpers](https://github.com/qtc-de/completion-helpers)
package. If *completion-helpers* is already installed, autocompletion for *kutil* should
work after installing the pip package. Otherwise, you may need to copy the completion
script manually:

```console
$ cp kutil/resources/bash_completion.d/kutil ~/.bash_completion.d
```


### Supported Operations

----

```console
$ kutil --help
usage: kutil [-h] [--aes-user username] [--aes-realm realm] [--aes-host hostname] [-c] [-d principal] [--delete index] [--decrypt key] [--hash password] [-i number] [-l] [-m path] [-o path] [-p PRINCIPAL]
             [--prefix PREFIX] [-r REALM] [-s SERVICE] [--spn SPN] [--split] [-t TARGET]
             [ticket]

kutil is a command line utility to work with Kerberos ticket cache files (MIT format). It can be used to merge different Kerberos tickets into a single ticket cache, to split or delete credentials from a ticket
cache or to modify the unencrypted portions of an existing ticket.

positional arguments:
  ticket                Kerberos ticket to operate on (default: /tmp/krb5cc_1000)

optional arguments:
  -h, --help            show this help message and exit
  --aes-user username   username for AES hash generation
  --aes-realm realm     realm for AES hash generation
  --aes-host hostname   hostname for AES hash generation
  -c, --clear           clear duplicate credentials
  -d principal, --default principal
                        update default principal of ccache
  --delete index        delete credential with specified index
  --decrypt key         decrypt credential selected by index
  --hash password       generate hashes for specified password
  -i number, --index number
                        ticket index for updates (default: 0)
  -l, --list            list ticket contents
  -m path, --merge path
                        merge specified ticket into main ticket (can be used multiple times)
  -o path, --out path   filename of the output ticket (default: ticket param)
  -p PRINCIPAL, --principal PRINCIPAL
                        update principal of credential selected by index
  --prefix PREFIX       filename prefix for split operation (default: cc_split_)
  -r REALM, --realm REALM
                        update the target realm of credential selected by index
  -s SERVICE, --service SERVICE
                        update service type (e.g. HTTP) of credential selected by index
  --spn SPN             update service SPN (e.g. service/target@realm) of credential slected by index
  --split               split ticket cache into seperate tickets
  -t TARGET, --target TARGET
                        update target server of credential selected by index
```


#### Credential Modifications

Operations that modify credentials stored inside a Kerberos ticket cache.

##### Change Principal

Changes the client principal for the credential specified by ``--index`` (default 0):

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --principal smeyer@example.lab
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating principal of credential with index 0
[+]     Old principal: 'administrator@EXAMPLE.LAB'
[+]     New principal: 'smeyer@example.lab'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	for client smeyer@example.lab, renew until 07/22/30 07:00:40
```

##### Change Realm

Changes the *realm* of the server principal for the credential specified by ``--index`` (default 0):

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --realm MODIFIED.LAB
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating realm of credential with index 0
[+]     Old realm: 'EXAMPLE.LAB'
[+]     New realm: 'MODIFIED.LAB'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@MODIFIED.LAB
	renew until 07/22/30 07:00:40
```

##### Change Service

Changes the *service type* of the server principal for the credential specified by ``--index`` (default 0):

```console
$ klist 
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --service LDAP
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating service of credential with index 0
[+]     Old service: 'http'
[+]     New service: 'LDAP'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

##### Change SPN

Changes the target *SPN* of a credential specified by ``--index`` (default 0). This is basically
an alternative to the ``--realm``, ``--service`` and ``--target`` parameters where you can specify
all options in one.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --spn LDAP/dc01.example.lab@EXAMPLE.LAB
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating SPN of credential with index 0
[+]     Old SPN: 'http/dev01.example.lab@EXAMPLE.LAB'
[+]     New SPN: 'LDAP/dc01.example.lab@EXAMPLE.LAB'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

##### Change Target

Change the target host of the server principal in the credential specified by ``--index`` (default 0):

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --target dev02.example.lab
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating target of credential with index 0
[+]     Old target: 'dev01.example.lab'
[+]     New target: 'dev02.example.lab'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev02.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```


#### Ticket Cache Modifications

Operations that modify the Kerberos ticket cache.

##### Clear Duplicates

Clears duplicate tickets from the ticket cache.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --clear
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Removing duplicate credentials from '/tmp/krb5cc_1000'.
[+] 1 duplicate credentials removed.
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

##### Change Default Principal

Changes the default principal of a ticket cache.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --default smeyer@EXAMPLE.LAB
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating default principal.
[+]     Old default principal: 'administrator@EXAMPLE.LAB'
[+]     New default principal: 'smeyer@EXAMPLE.LAB'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: smeyer@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	for client administrator@EXAMPLE.LAB, renew until 07/22/30 07:00:40
```

##### Delete Credential

Deletes a credential from the cache specified by an index.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --delete 1
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Deleting credential with index 1.
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

##### Merge Ticket Caches

Merges different Kerberos ticket caches.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --merge administrator.ccache 
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Kerberos ticket cache 'administrator.ccache' loaded.
[+] Adding 1 credential(s) to '/tmp/krb5cc_1000'
[+] Saving ticket as '/tmp/krb5cc_1000'
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

##### Split Ticket Caches

Split credentials of a Kerberos ticket cache into separate files.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  LDAP/dc01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --split
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Splitting /tmp/krb5cc_1000 into 2 separate tickets.
[+] Ticket cc_split_1 created.
[+] Ticket cc_split_2 created.
```


#### Miscellaneous

Other functions that can be useful when working with Kerberos tickets.

##### Decrypt Credential

Decrypts the credential specified by the ``--index`` parameter (default 0). Requires
the Kerberos hash for the corresponding credential.

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil --decrypt 139a228822914d0d20e13920b219121
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] 
[+] PAC Info Buffer:
[+]     ulType: 1
[+]     cbBufferSize: 456 bytes
[+]     Offset: 72 bytes
[+] 
[+] Authorization Data:
[+]     CommonHeader:                   
[...]
```

##### Hash Password

Computes Kerberos password hashes (NTLM, AES128, AES256) of the specified password.
This can be useful for the *decrypt* operation, as it requires the hashed password for a credential.

```console
$ kutil --hash password
[+] Generating hashes...
[+]    NTLM		: 8846F7EAEE8FB117AD06BDD830B7586C
[-] Notice: --aes-user or --aes-host and --aes-realm need to be supplied for AES hash calculation.
```

For computing *AES hashes* a username or computername and the corresponding realm are required:

```console
$ kutil --hash password --aes-user smeyer --aes-realm example.lab
[+] Generating hashes...
[+]    NTLM		    : 8846F7EAEE8FB117AD06BDD830B7586C
[+]    AES 128		: 8266333A9E151D16FAE6AD5AEF0DEF4D
[+]    AES 256		: 608504D6D78351369EAC5D9AB7B2F90D0BC2EA451C8BF76C91D3CA716D9F7887
```

##### List Ticket Cache

List contents of the ticket cache.

```console
$ kutil --list
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Primary Principal: b'administrator@EXAMPLE.LAB'
[+] Credentials: 
[+] [0]
[+] 	Client: b'administrator@EXAMPLE.LAB'
[+] 	Server: b'http/dev01.example.lab@EXAMPLE.LAB'
[+] 	Key: (0x17)b'6c4f65644771724c416767427743454e'
[+] 	Times: 
[+] 		Auth : 2020-07-24T07:00:40
[+] 		Start: 2020-07-24T07:00:40
[+] 		End  : 2030-07-22T07:00:40
[+] 		Renew: 2030-07-22T07:00:40
[+] 	SubKey: 0
[+] 	Flags: 0x50a00000
[+] 	Addresses: 0
[+] 	Auth Data: 0
[+] 	Ticket: b'618203b9308203b5a003020105a10d1b0b4558414d504c452e4c4142a2243022a003020101a11b30191b04687474701b1164657630312e6578616d706c652e6c6162a382037730820373a003020117a103020102a282036504820361ef0967adc54dd1d8fb35e980fabe346e8e95bd1555b44f23f9500731487a3d96cc2dbf759ce37ff1bd5aded25a04cae751b80735e4f225e66ae9bee021b52676af1c593afa9372d075bd01462a3a48ba855112140b4375da212d389089aceab517efb1cacab386017e086c91fb51b899accfa7ca67cea511bc56c0e6b0c1c0a888426273178ea938a266bfd0ada3c520b039eeb26373003cc85ae7b8473a78da36a78f80af9e347b02f691d16a16eb3b3a36542661cad526f59312d149e562e43b75add5a7d651ac50c703cea34d19d4a4e4e68d5e7526b5a8983518a799d3de73818e383244f1d5acb5ef5e4d0886800e7ba5e1879a47846835c4701ebec34801993e9cbee45daca2b64544ab946e312db4286e19667df02da546a8f48faecbb369ea8d1ce8e17a542c1593c872f76ae47acca2b9e26b0285348b0059a256454390abe6149bb89e86213104969923b64ee04625cb789a7fdecf21e9577f2390c728a3d12e968e5430e882a3f9cf4895a0b4809c319c942e7c587cd6b59468c67417b515e089ff833db666494f36acf7f27d5a11f914e898630d1af6a2d73f9897adc3190c53c4ad84efec15908fdd91464e03e00344c16a28fe26bca801f138f961e979bdefb09c1c32e0a433ad19696133db7c76b447105bce5043580be21c6fbc627ccdc61b1e7f7f0b1df36fd9390978687a5edfeca033d45d485c0fb5c469a1fae918f0030d5d76dff7957446f077b8db034a36ce557a87a30123b06414e80077bc6bb743156ccf435b16ec5f032bdcfdabc82bbdba39de67b2658615a8248606f4185aa4a229bcbce4376cf8b5313001fd6b1d8597de543a7da621c0bfb70b3ad1db4c2421272ddd041f0b01f1026a401cc32228af87da479a6488020578d1bfef02d6724dafeb8fa65a0573de9e22d78c3838bf97145cf901a9f5c904a3b1760b0ea8671d66a25e0da13039969b15ee9b6f3aa88200133e199643e730b9afcffc4cd76f308ce33bdae83c82e130e3ec688ec9b427611d0af9a8cde958e254015ce89ca71798410f7d36ac65f01733109f6c894f6e5ed15f090d1f0e3b024fdd4a4ade9eedf9d5bf1386ed7256d1f30406f73596ed6eb8801ef075620f230d66c39f6c1ff6ef55aa85aeb763a231be64fcd492e131f877068331a683355f1a9c36a455143246e920ed08c030cc544146d2f51ecd4c7548994590906357e1'
[+] 	Second Ticket: b''
```


### Why Modifying Tickets

----

A legitimate question is why it should be useful to modify the unencrypted portions of *Kerberos tickets*?
Actually, this was the initial functionality of *kutil* and the other functions were build later on.
So lets look at a scenario where changing tikcet contents can be useful.

Imagine you encounter an *HTTP Server* that is configured for *Kerberos Authentication* and you want to access
it with *Firefox*. Furthermore, let us assume that you have no valid credentials for a domain account, but
managed to obtain a service ticket (*TGS*) for a domain user. Therefore, your ticket cache could look like this:

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: smeyer@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  HTTP/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

After configuring *Firefox* for *Kerberos Authentication* with the corresponding domain, you will notice
that *Firefox* refuses to use the *TGS* and tries to access the webserver without authentication. The
reason for this behavior is that *GSSAPI* is quite picky when it comes down to comparing principal
names.

By hooking the ``gss_import_name`` function, you can verify that *Firefox* searches for a
credential matching the principal name ``HTTP@dev01.example.lab``. This format is called 
``NT-SRV-HST`` and does not contain the *realm* name explicitly (obviously, as *Firefox* could only
guess the actual *realm* of the domain). The credential inside the *ccache*, on the other hand,
is stored in the ``NT-SRV-INST`` format, that contains the *realm* name explicitly.

The *GSSAPI* documentation says, that the different principal name types do not matter during credential
lookups. However, this is only partially true as the explicit realm from the ``NT-SRV-INST`` type
seems to conflict with the missing realm in the ``NT-SRV-HST`` type. This is the reason why *Firefox*
does not find the corresponding credential and tries to access the webserver unauthenticated.

Solving the issue can be done in different ways. Initiall when I encountered this problem I hooked
the ``gss_import_name`` function and changed the ``NT-SRV-HST`` lookup into the ``NT-SRV-INST`` form.
However, with *kutil* where is an easier option. As mentioned above, the only conflicting part between
the two different principal name types is the explicit *realm* definition. By simply removing the
*realm* of the ``NT-SRV-INST`` type, *Firefox* will find the credential. The (probably) easiest
solution is therefore:

```console
$ kutil -r ''
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating realm of credential with index 0
[+]     Old realm: 'EXAMPLE.LAB'
[+]     New realm: ''
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: smeyer@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  HTTP/dev01.example.lab@
	renew until 07/22/30 07:00:40
```

Apart from this very specific example, changing the *service type* of a ticket can be quite useful.
*GSSAPI* uses case sensitive comparison when looking up credentials. A lookup for ``HTTP/dev01.example.lab@EXAMPLE.LAB``
does therefore not find the credential ``http/dev01.example.lab@EXAMPLE.LAB``. This can be annoying, but with *kutil*
it is easy to change:

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  http/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil -s HTTP
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating service of credential with index 0
[+]     Old service: 'http'
[+]     New service: 'HTTP'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  HTTP/dev01.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```

Finally, [this great article](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#solving-a-sensitive-problem)
on Kerberos constrained delegation demonstrates that ``S4U2Self`` can be quite useful to bypass limitations of
*Silver Tickets*. To utilize this, it is required to change the target host of a ``S4U2Self`` ticket. This can, again,
be easily done with *kutil*:

```console
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  cifs/serviceA$@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
$ kutil -t servicea.example.lab
[+] Kerberos ticket cache '/tmp/krb5cc_1000' loaded.
[+] Updating target of credential with index 0
[+]     Old target: 'serviceA$'
[+]     New target: 'servicea.example.lab'
[+] Saving ticket as '/tmp/krb5cc_1000'.
$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@EXAMPLE.LAB

Valid starting     Expires            Service principal
07/24/20 07:00:40  07/22/30 07:00:40  cifs/servicea.example.lab@EXAMPLE.LAB
	renew until 07/22/30 07:00:40
```


### Modifying Encrypted Ticket Content

-----

As *kutil* does already implement ticket decryption, one could also think about modifying the
encrypted portions of Kerberos tickets. However, once you have credentials for decrypting tickets
you could also just generate a new one using [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py). Therefore, modifying the encrypted
contents seems to be of limited use. That being said, modifying the unencrypted portions seemed
also not to be very useful until I encounterd the above described situation. So maybe this will
be implemented in future.



### Acknowledgements

-----

*kutil* does heavily rely on the [impacket](https://github.com/SecureAuthCorp/impacket) library. Furthermore, certain portions were copied
from other resources on *GitHub* (see comments in the source code). Thanks to all for sharing
your code :)


*Copyright 2020, Tobias Neitzel and the kutil contributors.*
