import pytest
from uuid import uuid4
import os

from pyeebus import x509_utils


@pytest.fixture
def setup():
    """
    https://docs.pytest.org/en/6.2.x/fixture.html#safe-teardowns
    """
    fn_basename = str(uuid4())
    public_key_fn = fn_basename + '.pem'
    private_key_fn = fn_basename + '.key'
    cert_fn = fn_basename + '.crt'
    
    yield public_key_fn, private_key_fn, cert_fn
    
    # this is executed when the test 'comes back here'
    try:
        os.remove(public_key_fn)
    except:
        pass
    try:
        os.remove(private_key_fn)
    except:
        pass
    try:
        os.remove(cert_fn)
    except:
        pass

def test_generate_keys_and_x509(setup):
    public_key_fn, private_key_fn, cert_fn = setup
    assert not os.path.isfile(public_key_fn)
    assert not os.path.isfile(private_key_fn)
    assert not os.path.isfile(cert_fn)

    x509_utils.generate_key(private_key_fn=private_key_fn, public_key_fn=public_key_fn)    
    assert os.path.isfile(public_key_fn)
    assert os.path.isfile(private_key_fn)

    x509_utils.generate_x509_keys_by_fn(public_key_pem_fn=public_key_fn, private_key_pem_fn=private_key_fn, cert_fn=cert_fn)
    assert os.path.isfile(cert_fn)

    ski = x509_utils.get_ski_from_pem_crt_file(cert_fn=cert_fn)
    assert ski