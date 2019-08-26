
from ctypes import *

class ksc_ffi:

	class log(Structure):
		pass

	class envelope(Structure):
		pass

	class data(Structure):
		pass

	class socket(Structure):
		pass

	def __init__(self):
		self._ksc = CDLL('libksc.so')

		ksc_log_p = POINTER(ksc_ffi.log)
		ksc_envelope_p = POINTER(ksc_ffi.envelope)
		ksc_data_p = POINTER(ksc_ffi.data)
		ksc_p = POINTER(ksc_ffi.socket)

		for k, v in {
			'log_create': (ksc_log_p, (c_int, c_char_p)),
			'log_restrict_context': (c_int, (ksc_log_p, c_char_p, c_char_p)),
			'envelope_get_source': (c_char_p, (ksc_envelope_p,)),
			'envelope_get_source_device_id': (c_int64, (ksc_envelope_p,)),
			'envelope_get_timestamp': (c_int64, (ksc_envelope_p,)),
			'data_get_body': (c_char_p, (ksc_data_p,)),
			'data_get_group_id_base64': (c_char_p, (ksc_data_p,)),
			'data_get_timestamp': (c_int64, (ksc_data_p,)),
			'get_udata': (c_void_p, (ksc_p,)),
			'start': (ksc_p, (c_char_p, # json_store_path
			                  CFUNCTYPE(c_int, ksc_p, ksc_envelope_p), # on_receipt
			                  CFUNCTYPE(c_int, ksc_p, ksc_envelope_p, ksc_data_p), # on_data
			                  CFUNCTYPE(None, ksc_p), # on_open
			                  CFUNCTYPE(None, c_void_p, c_void_p), # on_close
			                  ksc_log_p,
			                  c_char_p, # server_cert_path
			                  c_int, # on_close_do_reconnect
			                  c_void_p)),
			'stop': (None, (ksc_p,)),
			'send_message': (c_int, (ksc_p,
			                         c_char_p, # target
			                         c_char_p, # body
			                         CFUNCTYPE(c_int, c_int, c_char_p, c_void_p), # on_response
			                         c_void_p)),
		}.items():
			k2 = 'ksc_ffi_' + k
			(getattr(self._ksc, k2).restype, getattr(self._ksc, k2).argtypes) = v
			setattr(self, k, getattr(self._ksc, k2))

class ksc:
	def __init__(self):
		self._ffi = ksc_ffi()

	# level is one of 'none', 'error', 'warn', 'info', 'note', 'debug'
	def log_create(self, fd, level):
		return self._ffi.log_create(fd, level.encode())

	def log_restrict_context(self, log, desc, level):
		return self._ffi.log_restrict_context(log, desc.encode(),
		                                      level.encode())

	def start(self, json_store_path, server_cert_path, log = None,
	          on_receipt = None, on_data = None, on_open = None,
	          on_close = None, on_close_do_reconnect = False, data = None):
		if on_receipt is None:
			on_receipt = self._ffi.start.argtypes[1](0)
		if on_data is None:
			on_data = self._ffi.start.argtypes[2](0)
		if on_open is None:
			on_open = self._ffi.start.argtypes[3](0)
		if on_close is None:
			on_close = self._ffi.start.argtypes[4](0)
		return self._ffi.start(json_store_path.encode(), on_receipt,
		                       on_data, on_open, on_close, log,
		                       server_cert_path.encode(),
		                       on_close_do_reconnect, data)

	def stop(self, k):
		self._ffi.stop(k)

	def send_message(self, k, target, body, on_response = None, data = None):
		if on_response is None:
			on_response = self._ffi.send_message.argtypes[3](0)
		return self._ffi.send_message(k, target.encode(), body.encode(),
		                              on_response, data)

"""
from ksc import ksc
k = ksc()
log = k.log_create(2, 'note')
sock = k.start(LOCAL_PATH, 'share/whisper.store.asn1', log = log)
k.send_message(sock, NUMBER, 'hi from Python')
k.stop(sock)
"""
