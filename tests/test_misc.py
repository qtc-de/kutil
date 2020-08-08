#!/usr/bin/python3

import os
import kutil
import pytest


script = os.path.realpath(__file__)
folder = os.path.dirname(script)

ntlm_format = 'password, ntlm'
ntlm_probes = [
                ('password', '8846F7EAEE8FB117AD06BDD830B7586C'),
                (r'\S3cu\rP@$$w0rD', '80875FBA83A5E2EE50A117F3F5A01491'),
                ('', '31D6CFE0D16AE931B73C59D7E0C089C0')
              ]


aes_format = 'password, user, computer, domain, aes128, aes256'
aes_probes = [
                ('password', 'mmeyer', None, 'tets.lab', '97EA3F080CDF4653CF341FEF6A3D6E70',
                    'A27C0701AE6088EEAF21619AC47F8F98219BA08A5F53037C81AF17C00B47753C'),

                (r'\S3cu\rP@$$w0rD', None, 'web01.dev-domain.local', 'dev-domain.local',
                    '016A8CDF0362FCEE084C63F6699BF178', 'E4E3195559AE791AB58C28A2FEF6ADBB36618695EBE9FE9721BBBE044A6F2575'),

                ('', 'mme01r', None, 'tets01-1.lab', 'EADD1FC3DD9D7B2C79E89CD66F01AA7E',
                    'DD854A47B52313541CD05C64BEDF65382EC579E6CF6BF16BB38BF780050F552F')
             ]


@pytest.fixture(scope='function')
def ccache():
    '''
    Open a Kerberos credential cache and return the corresponding object.
    '''
    cc = kutil.open_ticket_cache(f'{folder}/example.ccache')
    return cc


@pytest.mark.parametrize(ntlm_format, ntlm_probes)
def test_ntlm_hash(password, ntlm):
    '''
    Compute the ntlm hash and compare it to the expected result.
    '''
    ntlm_hash = kutil.get_ntlm_hash(password)
    assert ntlm_hash == ntlm


@pytest.mark.parametrize(aes_format, aes_probes)
def test_aes_hash(password, user, computer, domain, aes128, aes256):
    '''
    Compute the aes hashes and compare them to the expected result.
    '''
    aes_hash = kutil.get_aes_hashes(password, user, computer, domain)
    assert aes_hash[0] == aes128
    assert aes_hash[1] == aes256


@pytest.mark.parametrize('index', [0, 1])
def test_decrypt(ccache, index):
    '''
    Attempts to decrypt the example Kerberos credential.
    '''
    pw_hash = '8846F7EAEE8FB117AD06BDD830B7586C'
    decrypted_ticket = kutil.decrypt_credential(ccache, index, pw_hash)
    assert decrypted_ticket is not None
