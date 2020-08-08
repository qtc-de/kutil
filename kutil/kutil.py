#!/usr/bin/python3

import sys
import struct
import hashlib
import binascii
from io import StringIO
from binascii import unhexlify, hexlify

from Crypto.Cipher import AES
from pyasn1.codec.der import decoder
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.pac import PACTYPE, VALIDATION_INFO


class KutilException(Exception):
    '''
    Custom Exception Class.
    '''


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

    for i in range(0, 32, dword):
        buffer_str = pac_data[i:i + dword]
        buffer_int = int(buffer_str, 16)
        buffer_str = hexlify(struct.pack('<L', buffer_int))
        buffer_int = int(buffer_str, 16)
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


def get_ntlm_hash(password):
    '''
    Computes the NTLM hash of the given password.

    Paramaters:
        password                    (string)                Password to hash

    Returns:
        ntlm_hash                   (string)                NTLM hashed password
    '''
    ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
    ntlm_hash = binascii.hexlify(ntlm_hash)
    ntlm_hash = ntlm_hash.decode('utf-8')

    return ntlm_hash.upper()


def get_aes_hashes(password, username=None, hostname=None, domain=None):
    '''
    Computes the AES hashes of the given password.

    Paramaters:
        password                    (string)                Password to hash
        username                    (string)                Corresponding username
        hostname                    (string)                Corresponding hostname
        domain                      (string)                Corresponding domain

    Returns:
        hashes                      (list[string])          [AES128,AES256]-Hashes
    '''
    hashes = []

    iv = b'\x00' * 16
    aes_constant = b'\x6B\x65\x72\x62\x65\x72\x6F\x73\x7B\x9B\x5B\x2B\x93\x13\x2B\x93'

    password = password.encode('utf-8')
    realm_upper = domain.upper()
    realm_lower = domain.lower()

    if username:
        salt = realm_upper + username
    else:
        salt = realm_upper + 'host' + hostname + '.' + realm_lower

    salt = salt.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 4096, 32)

    # AES128
    cipher = AES.new(key[0:16], AES.MODE_CBC, IV=iv)
    encrypted = cipher.encrypt(aes_constant)

    result = binascii.hexlify(encrypted).decode('utf-8')
    hashes.append(result.upper())

    # AES256
    aes_constant += b'\x5C\x9B\xDC\xDA\xD9\x5C\x98\x99\xC4\xCA\xE4\xDE\xE6\xD6\xCA\xE4'

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_part_1 = cipher.encrypt(aes_constant)

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_part_2 = cipher.encrypt(encrypted_part_1)

    result = binascii.hexlify(encrypted_part_1[0:16] + encrypted_part_2[0:16]).decode('utf-8')
    hashes.append(result.upper())

    return hashes


def split_cache(ccache, prefix='cc_split_'):
    '''
    Splits the specified ccache into a seperate cache for each credential.

    Paramaters:
        ccache                      (CCache)                CCache to split
        prefix                      (string)                Prefix name for splits

    Returns:
        names                       (list[string])          Split names
    '''
    count = 0
    names = []

    for credential in ccache.credentials:

        count += 1
        name = prefix + str(count)

        new_cc = CCache(data=ccache.getData())
        new_cc.credentials = [credential]

        new_cc.saveFile(name)
        names.append(name)

    return names


def clear_cache(ccache):
    '''
    Removes duplicate credentials from a CCache.

    Paramaters:
        ccache                      (CCache)                CCache to clear

    Returns:
        count                       (int)                   Number of removed credentials
    '''
    credential_hashes = []
    unique_credentials = []

    for credential in ccache.credentials:

        hash = hashlib.sha256(credential.getData()).hexdigest()
        if hash not in credential_hashes:

            unique_credentials.append(credential)
            credential_hashes.append(hash)

    duplicates = len(ccache.credentials) - len(unique_credentials)
    ccache.credentials = unique_credentials

    return duplicates


def merge_caches(main_cc, other):
    '''
    Merges the credential several {other} CCache objects into the {main_ccache} object.

    Paramaters:
        main_cc                     (CCache)                Merge into CCache
        other                       (list[CCache])          CCaches to merge

    Returns:
        tuple                       (tuple[int,int])        (merge_count, duplicate_count)
    '''
    credential_hashes = []

    for credential in main_cc.credentials:
        hash = hashlib.sha256(credential.getData()).hexdigest()
        credential_hashes.append(hash)

    count = 0
    credentials = []

    for ccache in other:
        for credential in ccache.credentials:

            hash = hashlib.sha256(credential.getData()).hexdigest()

            if hash in credential_hashes:
                count += 1
                continue

            credentials.append(credential)
            credential_hashes.append(hash)

    main_cc.credentials += credentials
    return (len(credentials), count)


def get_server_principal(ccache, index):
    '''
    Returns the server pricnipal of the credential {index}.

    Paramaters:
        ccache                      (CCache)                Kerberos credential cache
        index                       (int)                   nth Credential to select

    Returns:
        principal                   (Principal)             Server principal object
    '''
    try:
        credential = ccache.credentials[index]
        principal = credential.__getitem__('server')
        return principal

    except IndexError:
        raise KutilException(f"The specified index '{index}' is out of range.")


def get_client_principal(ccache, index):
    '''
    Returns the client pricnipal of the credential {index}.

    Paramaters:
        ccache                      (CCache)                Kerberos credential cache
        index                       (int)                   nth Credential to select

    Returns:
        principal                   (Principal)             Client principal object
    '''
    try:
        credential = ccache.credentials[index]
        principal = credential.__getitem__('client')
        return principal

    except IndexError:
        raise KutilException(f"The specified index '{index}' is out of range.")


def principal_get(principal, component):
    '''
    Returns the requested component of the principal object.

    Parameters:
        principal                   (Principal)             Principal to operate on
        component                   (string)                Component to return (target|service|realm)

    Returns:
        result                      (string)                Result for the requested component
    '''
    if component == 'service':
        component = principal.components[0]
        result = component['data'].decode('utf-8')

    elif component == 'target':
        component = principal.components[1]
        result = component['data'].decode('utf-8')

    elif component == 'realm':
        result = principal.realm['data'].decode('utf-8')

    return result


def format_client_principal(principal):
    '''
    Expects a client principal object as input and returns it formatted as '{user}@{realm}'.

    Paramaters:
        principal                   (Principal)             Client principal object

    Returns:
        result                      (string)                user@realm
    '''
    component = principal.components[0]

    user = component['data'].decode('utf-8')
    realm = principal.realm['data'].decode('utf-8')

    return f'{user}@{realm}'


def format_server_principal(principal):
    '''
    Expects a server principal object as input and returns it formatted as '{service}/{user}@{realm}'.

    Paramaters:
        principal                   (Principal)             Server principal object

    Returns:
        result                      (string)                service/user@realm
    '''
    component = principal.components[0]
    service = component['data'].decode('utf-8')

    component = principal.components[1]
    target = component['data'].decode('utf-8')

    realm = principal.realm['data'].decode('utf-8')

    return f'{service}/{target}@{realm}'


def format_default_principal(ccache):
    '''
    Returns the default principal of a CCache object in 'user@realm' format.

    Parameters:
        ccache                      (CCache)                Kerberos credential cache

    Returns:
        default_prrincipal          (string)                Default principal as string
    '''

    principal_object = ccache.principal.components[0]

    realm = ccache.principal.realm['data'].decode('utf-8')
    default_user = principal_object['data'].decode('utf-8')

    return f"{default_user}@{realm}"


def decrypt_credential(ccache, index, key):
    '''
    Decrypt credential from CCache. Copied from
    https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614

    Parameters:
        ccache                      (CCache)                Kerberos credential cache
        index                       (int)                   Credential index
        key                         (string)                decryption key

    Returns:
        decrypted_ticket            (bytes)                 decrypted ticket content
    '''
    try:
        credential = ccache.credentials[index]
        ticket = credential.ticket.getData()

    except IndexError:
        raise KutilException(f"The specified index '{index}' is out of range.")

    enc_type = credential['key']['keytype']

    try:
        if enc_type == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(enc_type, unhexlify(key))
        elif enc_type == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(enc_type, unhexlify(key))
        elif enc_type == EncryptionTypes.rc4_hmac.value:
            key = Key(enc_type, unhexlify(key))
        else:
            raise KutilException(f"Encryption type '{enc_type}' is not supported.")

    except (binascii.Error, ValueError) as e:
        raise KutilException("Error during key creation: " + str(e))

    cipher = _enctype_table[enc_type]

    spn_length = len(credential['server'].realm['data'])
    for i in credential['server'].toPrincipal().components:
        spn_length += len(i)

    encryption_offset = 128 + (2 * spn_length)
    encrypted_ticket = hexlify(ticket)[encryption_offset:]

    try:
        decrypted_ticket = cipher.decrypt(key, 2, unhexlify(encrypted_ticket))

    except InvalidChecksum as e:
        raise KutilException("Decryption error: " + str(e))

    return decrypted_ticket


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
