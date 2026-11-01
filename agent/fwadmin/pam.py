"""Senha conferida pelo PAM: a do usuario do sistema, criada na instalacao.

So funciona como root. O pam_unix de um processo sem privilegio confere a
senha pelo unix_chkpwd, que recusa conferir a de outro usuario: por isso quem
chama isto e' o `fwctl login`, via sudo, e nunca o painel direto.

ctypes sobre a libpam do sistema, sem dependencia nova: e' uma conversa de
uma pergunta so (a senha), e o resto e' o que o /etc/pam.d/azimuth mandar.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from ctypes import CFUNCTYPE, POINTER, Structure, c_char_p, c_int, c_void_p, cast, pointer, sizeof

SERVICE = "azimuth"
"""/etc/pam.d/azimuth: common-auth e common-account, como o login do console."""

PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_SUCCESS = 0
PAM_BUF_ERR = 5


class PamMessage(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class PamResponse(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]


CONV_FUNC = CFUNCTYPE(
    c_int, c_int, POINTER(POINTER(PamMessage)), POINTER(POINTER(PamResponse)), c_void_p
)


class PamConv(Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", c_void_p)]


def _libs():
    libpam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
    libc.calloc.restype = c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = c_void_p
    libc.strdup.argtypes = [c_char_p]
    libpam.pam_start.restype = c_int
    libpam.pam_start.argtypes = [c_char_p, c_char_p, POINTER(PamConv), POINTER(c_void_p)]
    libpam.pam_authenticate.restype = c_int
    libpam.pam_authenticate.argtypes = [c_void_p, c_int]
    libpam.pam_acct_mgmt.restype = c_int
    libpam.pam_acct_mgmt.argtypes = [c_void_p, c_int]
    libpam.pam_set_item.restype = c_int
    libpam.pam_set_item.argtypes = [c_void_p, c_int, c_void_p]
    libpam.pam_end.restype = c_int
    libpam.pam_end.argtypes = [c_void_p, c_int]
    return libpam, libc


PAM_RHOST = 4


def authenticate(username: str, password: str, rhost: str = "") -> bool:
    """Senha certa e conta valida (nao expirada nem travada)."""
    libpam, libc = _libs()
    secret = password.encode()

    @CONV_FUNC
    def conv(n, messages, responses, _appdata):
        # A libpam libera cada resp com free(): tem de vir do malloc da libc.
        buf = libc.calloc(n, sizeof(PamResponse))
        if not buf:
            return PAM_BUF_ERR
        responses[0] = cast(buf, POINTER(PamResponse))
        for i in range(n):
            if messages[i].contents.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                responses[0][i].resp = libc.strdup(secret)
            responses[0][i].resp_retcode = 0
        return PAM_SUCCESS

    handle = c_void_p()
    if libpam.pam_start(SERVICE.encode(), username.encode(), pointer(PamConv(conv, None)), pointer(handle)) != PAM_SUCCESS:
        return False
    rc = PAM_SUCCESS
    try:
        if rhost:
            # O pam_unix registra no journal de onde veio a tentativa.
            libpam.pam_set_item(handle, PAM_RHOST, cast(c_char_p(rhost.encode()), c_void_p))
        rc = libpam.pam_authenticate(handle, 0)
        if rc == PAM_SUCCESS:
            rc = libpam.pam_acct_mgmt(handle, 0)
        return rc == PAM_SUCCESS
    finally:
        libpam.pam_end(handle, rc)
