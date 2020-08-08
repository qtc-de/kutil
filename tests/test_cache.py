#!/usr/bin/python3

import os
import kutil
import pytest


script = os.path.realpath(__file__)
folder = os.path.dirname(script)


@pytest.fixture(scope='function')
def ccache():
    '''
    Open a Kerberos credential cache and return the corresponding object.
    '''
    cc = kutil.open_ticket_cache(f'{folder}/example.ccache')
    return cc


def test_duplicates(ccache):
    '''
    Create duplicate and try to clear it (example cache contains 1 dup).
    '''
    credential_count = len(ccache.credentials)
    kutil.clear_cache(ccache)

    assert credential_count - 1 == len(ccache.credentials)


def test_merge(ccache):
    '''
    Attempts to merge another example credential cache.
    '''
    cc = kutil.open_ticket_cache(f'{folder}/example2.ccache')
    merged, duplicates = kutil.merge_caches(ccache, [cc])

    assert merged == 1
    assert duplicates == 0


def test_split(ccache):
    '''
    Attempts to split the example credential cache.
    '''
    names = kutil.split_cache(ccache, 'cc_sample_')
    for name in names:
        assert os.path.isfile(name)
        os.remove(name)
