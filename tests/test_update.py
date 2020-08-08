#!/usr/bin/python3

import os
import kutil
import pytest


script = os.path.realpath(__file__)
folder = os.path.dirname(script)

realm_format = 'realm, index'
realm_probes = [('test.local', 0), ('test123.l0cal', 1), ('test-domain.local', 1)]

service_format = 'service, index'
service_probes = [('HTTP', 0), ('wsman', 1), ('CiFs', 1)]

target_format = 'target, index'
target_probes = [('dev.test.lab', 0), ('dev01.test123.l0cal', 1), ('dev-01.test-domain.local', 1)]

spn_format = 'spn, index'
spn_probes = [
                ('HTTP/dev.test.lab@test.lab', 0),
                ('wsman/dev01.test123.l0cal@test123.l0cal', 1),
                ('CiFs/dev-01.test-domain.local@test-domain.local', 1)
             ]

principal_format = 'principal_value, index'
principal_probes = [('mmeyer@test.lab', 0), ('m-meyer@test123.l0cal', 1), ('m-meyer01@test-domain.local', 1)]

default_format = 'default'
default_probes = ['mmeyer@test.lab', 'm-meyer@test123.l0cal', 'm-meyer01@test-domain.local']


@pytest.fixture(scope='function')
def ccache():
    '''
    Open a Kerberos credential cache and return the corresponding object.
    '''
    cc = kutil.open_ticket_cache(f'{folder}/example.ccache')
    return cc


@pytest.mark.parametrize(realm_format, realm_probes)
def test_update_realm(ccache, realm, index):
    '''
    Update the realm of a principal inside the credential cache.
    '''
    principal = kutil.get_server_principal(ccache, index)
    kutil.update_realm(principal, realm)

    principal = kutil.get_server_principal(ccache, index)
    new_realm = kutil.principal_get(principal, 'realm')

    assert new_realm == realm


@pytest.mark.parametrize(service_format, service_probes)
def test_update_service(ccache, service, index):
    '''
    Update the service of a principal inside the credential cache.
    '''
    principal = kutil.get_server_principal(ccache, index)
    kutil.update_service(principal, service)

    principal = kutil.get_server_principal(ccache, index)
    new_service = kutil.principal_get(principal, 'service')

    assert new_service == service


@pytest.mark.parametrize(target_format, target_probes)
def test_update_target(ccache, target, index):
    '''
    Update the target of a principal inside the credential cache.
    '''
    principal = kutil.get_server_principal(ccache, index)
    kutil.update_target(principal, target)

    principal = kutil.get_server_principal(ccache, index)
    new_target = kutil.principal_get(principal, 'target')

    assert new_target == target


@pytest.mark.parametrize(spn_format, spn_probes)
def test_update_spn(ccache, spn, index):
    '''
    Update the spn of a principal inside the credential cache.
    '''
    principal = kutil.get_server_principal(ccache, index)
    kutil.update_spn(principal, spn)

    principal = kutil.get_server_principal(ccache, index)
    new_spn = kutil.format_server_principal(principal)

    assert new_spn == spn


@pytest.mark.parametrize(principal_format, principal_probes)
def test_update_principal(ccache, principal_value, index):
    '''
    Update the client principal inside the credential cache.
    '''
    principal = kutil.get_client_principal(ccache, index)
    kutil.update_principal(principal, principal_value)

    principal = kutil.get_client_principal(ccache, index)
    new_principal = kutil.format_client_principal(principal)

    assert new_principal == principal_value


@pytest.mark.parametrize(default_format, default_probes)
def test_update_default(ccache, default):
    '''
    Update the default principal inside the credential cache.
    '''
    kutil.update_default_principal(ccache, default)
    new_default = kutil.format_default_principal(ccache)

    assert new_default == default
