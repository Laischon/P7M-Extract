import sys
from OpenSSL import crypto
from OpenSSL._util import (
	ffi as _ffi,
	lib as _lib,
)

with open(sys.argv[1], 'rb') as f:
	p7data = f.read()
p7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, p7data)

bio_out =crypto._new_mem_buf()
res = _lib.PKCS7_verify(p7._pkcs7, _ffi.NULL, _ffi.NULL, _ffi.NULL, bio_out, _lib.PKCS7_NOVERIFY|_lib.PKCS7_NOSIGS)
if res == 1:
	databytes = crypto._bio_to_string(bio_out)
	print(databytes)
else:
	errno = _lib.ERR_get_error()
	errstrlib = _ffi.string(_lib.ERR_lib_error_string(errno))
	errstrfunc = _ffi.string(_lib.ERR_func_error_string(errno))
	errstrreason = _ffi.string(_lib.ERR_reason_error_string(errno))
	print(errstrreason)
