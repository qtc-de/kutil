#!/usr/bin/python3

import os
import sys
import struct
import hashlib
import argparse
import binascii
from io import StringIO
from binascii import unhexlify,hexlify,Error

from Crypto.Cipher import AES
from pyasn1.codec.der import encoder, decoder


default_cache = '/tmp/krb5cc_' + str(os.getuid())


class KutilException(Exception):
    '''
    Custom Exception Class.
    '''


def add_prefix(text, prefix='[+] '):
    '''
    Adds the specified prefix in front of each line in {text}.

    Parameters:
        text                        (string)                Text to apply prefix
        prefix                      (string)                Prefix to apply

    Returns:
        prefixed_text               (string)                Prefixed text
    '''
    prefixed_lines = []
    lines = text.split('\n')

    for line in lines:
        prefixed_line = prefix + line
        prefixed_lines.append(prefixed_line)

    return '\n'.join(prefixed_lines)


def open_ticket_cache(path):
    '''
    Attempts to open {path} as a Kerberos5 Ticket Cache. If this is not possible
    (file not exists, no permissions, format is no Kerberos Ticket Cache), the
    functions throws a KutilException with the corresponding error message.

    Parameters:
        path                        (string)                Path to the cache file

    Returns:
        None
    '''
    try:
        ccache = CCache.loadFile(path)
        return ccache
    except FileNotFoundError:
        error = f"Kerberos ticket cache '{path}' does not exist."
    except PermissionError:
        error = f"Insufficient permissions to open '{path}'"
    except struct.error:
        error = f"Unable to parse '{path}' as Kerberos ticket cache"

    raise KutilException(error)


def update_counted_octet_string(counted_octed_string, data):
    '''
    Set new content to the 'data' field of a CountedOctetString and update
    the length fields accordingly.

    Parameters:
        counted_octet_string        (CountedOctetString)    Object to update
        data                        (byte)                  Data to set

    Returns:
        None
    '''
    counted_octed_string['_data'] = len(data)
    counted_octed_string['length'] = len(data)
    counted_octed_string['data'] = data


def process_pac_info_buffer(pac_data):
    '''
    Function to parse the PAC_INFO_BUFFER.
    Taken from https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614.

    Parameters:
        pac_data                    (byte)                  PAC data as bytes

    Returns:
        buffer_list                 (list[int])             List of parsed integers
    '''
    dword = 8
    buffer_list = []

    for i in range(0,32,dword):
        buffer_str = pac_data[i:i+dword]
        buffer_int = int(buffer_str,16)
        buffer_str = hexlify(struct.pack('<L',buffer_int))
        buffer_int = int(buffer_str,16)
        buffer_list.append(buffer_int)

    return buffer_list


def parse_ticket(decrypted_ticket):
    '''
    Parses the authorization data of a decrypted Kerberos ticket.

    Parameters:
        decrypted_ticket            (byte)                  Decrypted Kerberos ticket

    Returns:
        parsed_ticket               (string)                Parsed and formatted Kerberos ticket
    '''
    decoded_ticket = decoder.decode(decrypted_ticket)[0]
    pac_data = decoded_ticket['field-9'][0]['field-1']
    dec_auth_data = decoder.decode(pac_data)[0][0]['field-1']

    pac_buffers = PACTYPE(dec_auth_data.__bytes__())
    pac_buffer = pac_buffers['Buffers']
    pac_buffer_hex = hexlify(pac_buffer)

    pac_info_list = process_pac_info_buffer(pac_buffer_hex)
    auth_data_type = pac_info_list[0]
    auth_data_length = pac_info_list[1]
    auth_data_offset = pac_info_list[2]
    auth_data_end = (auth_data_length * 2) - 40
    offset_start = 24 + auth_data_offset * 2
    auth_data_hex = pac_buffer_hex[offset_start:offset_start + auth_data_end]

    sys.stdout = output = StringIO()

    print("\nPAC Info Buffer:")
    print("    ulType: " + str(auth_data_type))
    print("    cbBufferSize: " + str(auth_data_length) + " bytes")
    print("    Offset: " + str(auth_data_offset) + " bytes")
    
    final_validation_info = VALIDATION_INFO()
    final_validation_info.fromStringReferents(unhexlify(auth_data_hex))
    final_validation_info.dump()

    sys.stdout = sys.__stdout__
    output = output.getvalue()

    indent = ''
    parsed_ticket = []
    for line in output.splitlines():

        if line == 'VALIDATION_INFO ':
            indent = '    '
            parsed_ticket.append('\nAuthorization Data:') 
            continue

        line = indent + line
        parsed_ticket.append(line)

    parsed_ticket = '\n'.join(parsed_ticket)

    return parsed_ticket


def update_realm(principal, realm):
    '''
    Updates the realm of a principal object.

    Parameters:
        principal                   (Principal)             Principal object
        realm                       (string)                Realm name as string

    Returns:
        None
    '''
    brealm = realm.encode('utf-8')
    update_counted_octet_string(principal.realm, brealm)


def update_service(principal, service):
    '''
    Updates the service type of a principal object.

    Parameters:
        principal                   (Principal)             Principal object
        service                     (string)                Service type as string

    Returns:
        None
    '''
    bservice = service.encode('utf-8')
    service_component = principal.components[0]
    update_counted_octet_string(service_component, bservice)


def update_target(principal, target):
    '''
    Updates the target server of a principal object.

    Parameters:
        principal                   (Principal)             Principal object
        target                      (string)                Target server as string

    Returns:
        None
    '''
    btarget = target.encode('utf-8')
    target_component = principal.components[1]
    update_counted_octet_string(target_component, btarget)


def update_spn(principal, spn):
    '''
    Updates the realm, service type and target server of a principal object according
    to the specified {spn}. The SPN is expected in the format: 'service/target@realm'.

    Parameters:
        principal                   (Principal)             Principal object
        spn                         (string)                SPN as string

    Returns:
        None
    '''
    split = spn.split('/')
    split2 = split[1].split('@')

    if len(split) != 2 or len(split2) != 2:
        error = "SPN is expected in the format: 'service/target@domain'"
        raise KutilException(error)

    update_realm(principal, split2[1])
    update_target(principal, split2[0])
    update_service(principal, split[0])


def update_principal(principal, principal_new):
    '''
    Updates the client principal of a principal object. The new principal is expected
    as: 'user@domain'.

    Parameters:
        principal                   (Principal)             Principal object
        principal_new               (string)                Principal as string

    Returns:
        None
    '''
    split = principal_new.split('@')

    if len(split) != 2:
        error = "Principal is expected in the format: 'user@domain'"
        raise KutilException(error)

    buser = split[0].encode('utf-8')
    bdomain = split[1].encode('utf-8')

    update_counted_octet_string(principal.realm, bdomain)
    client_component = principal.components[0]
    update_counted_octet_string(client_component, buser)


def update_default_principal(ccache, principal):
    '''
    Updates the default principal of a CCache object. The new principal is expected
    as: 'user@domain'.

    Parameters:
        principal                   (Principal)             Principal object
        principal_new               (string)                Principal as string

    Returns:
        None
    '''
    split = principal.split('@')

    if len(split) != 2:
        error = "Principal is expected in the format: 'user@domain'"
        raise KutilException(error)

    buser = split[0].encode('utf-8')
    bdomain = split[1].encode('utf-8')
    principal = ccache.principal

    update_counted_octet_string(principal.realm, bdomain)
    client_component = principal.components[0]
    update_counted_octet_string(client_component, buser)


parser = argparse.ArgumentParser(description='''kutil is a command line utility to work with Kerberos
                                                ticket cache files (MIT format). It can be used to merge
                                                different Kerberos tickets into a single ticket cache,
                                                to split or delete credentials from a ticket cache or to
                                                modify the unencrypted portions of an existing ticket.''')

parser.add_argument('ticket', nargs='?', default=default_cache, help=f'Kerberos ticket to operate on (default: {default_cache})')
parser.add_argument('--aes-user', metavar='USERNAME', dest='username', help='username for AES hash generation')
parser.add_argument('--aes-realm', metavar='REALM', dest='domain', help='realm for AES hash generation')
parser.add_argument('--aes-host', metavar='HOSTNAME', dest='hostname', help='hostname for AES hash generation')
parser.add_argument('-c', '--clear', action='store_true', help='clear duplicate credentials')
parser.add_argument('-d', '--default', metavar='PRINCIPAL', help='update default principal of ccache')
parser.add_argument('--delete', metavar='INDEX', type=int, help='delete credential with specified index')
parser.add_argument('--decrypt', metavar='KEY', help='decrypt credential selected by index')
parser.add_argument('--hash', metavar='PASSWORD', help='generate hashes for specified password')
parser.add_argument('-i', '--index', type=int, metavar='NUMBER', default=0, help='ticket index for updates (default: 0)')
parser.add_argument('-l', '--list', action='store_true', help=f'list ticket contents')
parser.add_argument('-m', '--merge', metavar='PATH', action='append', default=[], help='merge specified ticket into main ticket (can be used multiple times)')
parser.add_argument('-o', '--out', metavar='PATH', help=f'filename of the output ticket (default: ticket param)')
parser.add_argument('-p', '--principal', help='update principal of credential selected by index')
parser.add_argument('--prefix', default='cc_split_', help='filename prefix for split operation (default: cc_split_)')
parser.add_argument('-r', '--realm', help='update the target realm of credential selected by index')
parser.add_argument('-s', '--service', help='update service type (e.g. HTTP) of credential selected by index')
parser.add_argument('--spn', help='update service SPN (e.g. service/target@realm) of credential slected by index')
parser.add_argument('--split', action='store_true', help='split ticket cache into seperate tickets')
parser.add_argument('-t', '--target', help='update target server of credential selected by index')
args = parser.parse_args()

# impacket CCache is first loaded after args were parsed. This improves startup time when using -h or --help
from impacket.krb5.ccache import CCache

#######################################################################################
#####                              Generate Hashes                                #####
#####  https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372   #####
#######################################################################################
if args.hash is not None:

    password = args.hash
    print(f"[+] Generating hashes...")

    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    ntlm_hash = binascii.hexlify(ntlm_hash)
    ntlm_hash = ntlm_hash.decode('utf-8')
    print(f"[+]    NTLM\t\t: {ntlm_hash.upper()}")

    if not ( (args.username or args.hostname) and args.domain):
        print(f"[-] Notice: --aes-user or --aes-host and --aes-realm need to be supplied for AES hash calculation.")
        sys.exit(0)

    iv=b'\x00' * 16
    aes_constant  = b'\x6B\x65\x72\x62\x65\x72\x6F\x73\x7B\x9B\x5B\x2B\x93\x13\x2B\x93'

    password = args.hash.encode('utf-8')
    realm_upper = args.domain.upper()
    realm_lower = args.domain.lower()

    if args.username:
        salt = realm_upper + args.username
    else:
        salt = realm_upper + 'host' +  args.hostname + '.' + realm_lower

    salt = salt.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 4096, 32)

    # AES128
    cipher = AES.new(key[0:16], AES.MODE_CBC, IV=iv)
    encrypted = cipher.encrypt(aes_constant)

    result = binascii.hexlify(encrypted).decode('utf-8')
    print(f"[+]    AES 128\t\t: {result.upper()}")

    # AES256
    aes_constant += b'\x5C\x9B\xDC\xDA\xD9\x5C\x98\x99\xC4\xCA\xE4\xDE\xE6\xD6\xCA\xE4'

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_part_1 = cipher.encrypt(aes_constant)

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_part_2 = cipher.encrypt(encrypted_part_1)

    result = binascii.hexlify(encrypted_part_1[0:16] + encrypted_part_2[0:16]).decode('utf-8')
    print(f"[+]    AES 256\t\t: {result.upper()}")

    sys.exit(0)


#######################################################################################
#####                               Ticket Setup                                  #####
#######################################################################################
args.out = args.out if args.out else args.ticket

try:
    main_cc = open_ticket_cache(args.ticket)
    credential_count = len(main_cc.credentials)

    if args.index is not None and args.index >= credential_count:
        print(f"[-] Specified credential index '{args.index}' is out of range.")
        print(f"[-]     Only {credential_count} credential(s) are currently cached.")
        print(f"[-]     The maximum credential index is thereby {credential_count - 1}.")
        sys.exit(1)

    print(f"[+] Kerberos ticket cache '{args.ticket}' loaded.")

except KutilException as e:
    print("[-] " + str(e))
    sys.exit(1)


#######################################################################################
#####                              Split Operation                                #####
#######################################################################################
if args.split:

    count = 0
    prefix = args.prefix

    print(f"[+] Splitting {args.ticket} into {credential_count} separate tickets.")
    for credential in main_cc.credentials:

        count += 1
        name = prefix + str(count)

        new_cc = CCache(data=main_cc.getData())
        new_cc.credentials = [credential]

        new_cc.saveFile(name)
        print(f"[+] Ticket {name} created.")

    sys.exit(0)


#######################################################################################
#####                              Merge Operation                                #####
#######################################################################################
if args.merge:

    try:
        cc_list = []
        for ccache in args.merge:
            additional_cc = open_ticket_cache(ccache)
            cc_list.append(additional_cc)
            print(f"[+] Kerberos ticket cache '{ccache}' loaded.")

    except KutilException as e:
        print("[-] " + str(e))
        sys.exit(1)

    credential_hashes = []
    for credential in main_cc.credentials:
        hash = hashlib.sha256(credential.getData()).hexdigest()
        credential_hashes.append(hash)

    count = 0
    credentials = []

    for ccache in cc_list:
        for credential in ccache.credentials:
            hash = hashlib.sha256(credential.getData()).hexdigest()
            if hash in credential_hashes:
                count += 1
                continue
            credentials.append(credential)
            credential_hashes.append(hash)

    if count != 0:
        print(f"[+] {count} duplicate credential(s) were not added to '{args.ticket}'")

    if len(credentials) != 0:
        print(f"[+] Adding {len(credentials)} credential(s) to '{args.ticket}'")
        main_cc.credentials += credentials

        print(f"[+] Saving ticket as '{args.out}'")
        main_cc.saveFile(args.out)

    sys.exit(0)


#######################################################################################
#####                              Change Principal                               #####
#######################################################################################
if args.default is not None:

    old_user = ((main_cc.principal.components[0])['data']).decode('utf-8')
    old_realm = (main_cc.principal.realm['data']).decode('utf-8')
    old_default = f"{old_user}@{old_realm}"

    print(f"[+] Updating default principal.")
    print(f"[+]     Old default principal: '{old_default}'")

    try:
        update_default_principal(main_cc, args.default)
    except KutilException as e:
        print("[-] " + str(e))
        sys.exit(1)

    new_user = ((main_cc.principal.components[0])['data']).decode('utf-8')
    new_realm = (main_cc.principal.realm['data']).decode('utf-8')
    new_default = f"{new_user}@{new_realm}"

    print(f"[+]     New default principal: '{new_default}'")
    print(f"[+] Saving ticket as '{args.out}'.")

    main_cc.saveFile(args.out)


#######################################################################################
#####                                Change Realm                                 #####
#######################################################################################
if args.realm is not None:

    credential = main_cc.credentials[args.index]
    principal = credential.__getitem__('server')
    old_realm = (principal.realm['data']).decode('utf-8')

    print(f"[+] Updating realm of credential with index {args.index}")
    print(f"[+]     Old realm: '{old_realm}'")

    update_realm(principal, args.realm)
    new_realm = (principal.realm['data']).decode('utf-8')
    print(f"[+]     New realm: '{new_realm}'")

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                               Change Service                                #####
#######################################################################################
if args.service is not None:

    credential = main_cc.credentials[args.index]
    principal = credential.__getitem__('server')
    old_service = ((principal.components[0])['data']).decode('utf-8')

    print(f"[+] Updating service of credential with index {args.index}")
    print(f"[+]     Old service: '{old_service}'")

    update_service(principal, args.service)
    new_service = ((principal.components[0])['data']).decode('utf-8')
    print(f"[+]     New service: '{new_service}'")

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                               Change Target                                 #####
#######################################################################################
if args.target is not None:

    credential = main_cc.credentials[args.index]
    principal = credential.__getitem__('server')
    old_target = ((principal.components[1])['data']).decode('utf-8')

    print(f"[+] Updating target of credential with index {args.index}")
    print(f"[+]     Old target: '{old_target}'")

    update_target(principal, args.target)
    new_target = ((principal.components[1])['data']).decode('utf-8')
    print(f"[+]     New target: '{new_target}'")

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                              Change Principal                               #####
#######################################################################################
if args.principal is not None:

    credential = main_cc.credentials[args.index]
    principal = credential.__getitem__('client')

    old_user = ((principal.components[0])['data']).decode('utf-8')
    old_realm = (principal.realm['data']).decode('utf-8')
    old_principal = f"{old_user}@{old_realm}"

    print(f"[+] Updating principal of credential with index {args.index}")
    print(f"[+]     Old principal: '{old_principal}'")

    try:
        update_principal(principal, args.principal)
    except KutilException as e:
        print("[-] " + str(e))
        sys.exit(1)

    new_user = ((principal.components[0])['data']).decode('utf-8')
    new_realm = (principal.realm['data']).decode('utf-8')
    new_principal = f"{new_user}@{new_realm}"

    print(f"[+]     New principal: '{new_principal}'")

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                                Change SPN                                   #####
#######################################################################################
if args.spn is not None:

    credential = main_cc.credentials[args.index]
    principal = credential.__getitem__('server')

    old_realm = (principal.realm['data']).decode('utf-8')
    old_target = ((principal.components[1])['data']).decode('utf-8')
    old_service = ((principal.components[0])['data']).decode('utf-8')
    old_spn = f"{old_service}/{old_target}@{old_realm}"

    print(f"[+] Updating SPN of credential with index {args.index}")
    print(f"[+]     Old SPN: '{old_spn}'")

    try:
        update_spn(principal, args.spn)
    except KutilException as e:
        print("[-] " + str(e))
        sys.exit(1)

    new_realm = (principal.realm['data']).decode('utf-8')
    new_target = ((principal.components[1])['data']).decode('utf-8')
    new_service = ((principal.components[0])['data']).decode('utf-8')
    new_spn = f"{new_service}/{new_target}@{new_realm}"
    print(f"[+]     New SPN: '{new_spn}'")

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                             Clear Duplicates                                #####
#######################################################################################
if args.clear:

    credential_hashes = []
    unique_credentials = []

    print(f"[+] Removing duplicate credentials from '{args.ticket}'.")
    for credential in main_cc.credentials:

        hash = hashlib.sha256(credential.getData()).hexdigest()
        if hash not in credential_hashes:

            unique_credentials.append(credential)
            credential_hashes.append(hash)

    duplicates = credential_count - len(unique_credentials)
    print(f"[+] {duplicates} duplicate credentials removed.")
    main_cc.credentials = unique_credentials

    if duplicates != 0:

        print(f"[+] Saving ticket as '{args.out}'.")
        main_cc.saveFile(args.out)


#######################################################################################
#####                             Delete Credential                               #####
#######################################################################################
if args.delete is not None:

    print(f"[+] Deleting credential with index {args.delete}.")
    del main_cc.credentials[args.delete]

    print(f"[+] Saving ticket as '{args.out}'.")
    main_cc.saveFile(args.out)


#######################################################################################
#####                                List Ticket                                  #####
#######################################################################################
if args.list:

    sys.stdout = output = StringIO()
    main_cc.prettyPrint()
    sys.stdout = sys.__stdout__

    output = output.getvalue()
    output = add_prefix(output)
    print(output)


#######################################################################################
#####                             Decrypt Credential                              #####
##### Copied from: https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614 #####
#######################################################################################
if args.decrypt:

    # impacket modules have a long load time. Therefore they are only loaded when required.
    from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
    from impacket.krb5.constants import EncryptionTypes
    from impacket.krb5.pac import PACTYPE, VALIDATION_INFO

    key = args.decrypt
    credential = main_cc.credentials[args.index]
    ticket = credential.ticket.getData()

    enc_type = credential['key']['keytype']

    try:
        if enc_type == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(enc_type, unhexlify(key))
        elif enc_type == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(enc_type, unhexlify(key))
        elif enc_type == EncryptionTypes.rc4_hmac.value:
            key = Key(enc_type, unhexlify(key))
        else:
            print(f"[-] Encryption type '{enc_type}' of credential with index '{args.index}' is not supported.")
            sys.exit(1)
    except (binascii.Error,ValueError) as e:
        print(f"[-] Error during key creation: " + str(e))
        sys.exit(1)

    cipher = _enctype_table[enc_type]

    spn_length = len(credential['server'].realm['data'])
    for i in credential['server'].toPrincipal().components:
        spn_length += len(i)
    
    encryption_offset = 128 + (2 * spn_length)
    encrypted_ticket = hexlify(ticket)[encryption_offset:]

    try:
        decrypted_ticket = cipher.decrypt(key, 2, unhexlify(encrypted_ticket))
    except InvalidChecksum as e:
        print(f"[-] Decryption error: " + str(e))
        sys.exit(1)

    parsed_ticket = parse_ticket(decrypted_ticket)
    parsed_ticket = add_prefix(parsed_ticket)

    print(parsed_ticket)
