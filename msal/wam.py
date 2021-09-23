"""This module acquires token via WAM, with the help of Mid-tier.

Mid-tier supports these Windows versions
https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2406/files
"""
from threading import Event
import pymsalruntime  # See https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2419/files#diff-d5ea5122ff04e14411a4f695895c923daba73c117d6c8ceb19c4fa3520c3c08a


class _CallbackData:
    def __init__(self):
        self.signal = Event()
        self.auth_result = None

    def complete(self, auth_result):
        self.signal.set()
        self.auth_result = auth_result


def _read_account_by_id(account_id):
    callback_data = _CallbackData()
    pymsalruntime.read_account_by_id(
        account_id,
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

def _signin_silent():
    callback_data = _CallbackData()
    pymsalruntime.signin_silent(
        # TODO: Add other input parameters
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

def _signin_interactive():
    callback_data = _CallbackData()
    pymsalruntime.signin_interactive(
        # TODO: Add other input parameters
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

def _acquire_token_silently(authority, client_id, account):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    callback_data = _CallbackData()
    pymsalruntime.signin_interactive(
        params,
        "correlation", # TODO
        account,
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

def _acquire_token_interactive(
        authority,
        client_id,
        account,
        scopes,
        prompt=None,  # TODO: Perhaps WAM would not accept this?
        login_hint=None,  # type: Optional[str]
        domain_hint=None,  # TODO: Perhaps WAM would not accept this?
        claims_challenge=None,
        timeout=None,  # TODO
        extra_scopes_to_consent=None,  # TODO: Perhaps WAM would not accept this?
        max_age=None,  # TODO: Perhaps WAM would not accept this?
        **kwargs):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(" ".join(scopes))
    if login_hint:
        params.set_login_hint(login_hint)
    if claims_challenge:
        params.set_claims(claims_challenge
    # TODO: Wire up other input parameters too
    callback_data = _CallbackData()
    pymsalruntime.signin_interactive(
        params,
        "correlation", # TODO
        account,
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result


def acquire_token_interactive(
        authority,  # type: str
        client_id,  # type: str
        scopes,  # type: list[str]
        **kwargs):
    """MSAL Python's acquire_token_interactive() will call this"""
    result = _signin_silent(authority, client_id)
    if not result.get_account():
        result = _signin_interactive(authority, client_id)
    if not result.get_account():
        return {"error": result.get_error()}  # TODO

    result = _acquire_token_silently(
        authority, client_id, account, scopes, **kwargs)
    if not result.get_access_token():
        result = _acquire_token_interactive(
            authority, client_id, account, scopes, **kwargs)
    if not result.get_access_token():
        return {"error": result.get_error()}  # TODO
    # TODO: Also store the tokens and account into MSAL's token cache
    return {k: v for k, v in {
        "access_token": result.get_access_token(),
        "token_type": "Bearer",  # TODO: TBD
        "expires_in": result.get_access_token_expiry_time(),
        "id_token": result.get_id_token(),
        "scope": result.get_granted_scopes(),
        } if v is not None}


def acquire_token_silent(
        authority,  # type: str
        client_id,  # type: str
        scopes,  # type: list[str]
        account,
        ):
    wam_account = _read_account_by_id(account["some_sort_of_id"])  # TODO
    if wam_account:
        return _acquire_token_silently(authority, client_id, scopes, wam_account)

