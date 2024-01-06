﻿import json
import threading
import time
import logging

from .authority import canonicalize
from .oauth2cli.oidc import decode_part, decode_id_token
from .oauth2cli.oauth2 import Client


logger = logging.getLogger(__name__)
_GRANT_TYPE_BROKER = "broker"

def is_subdict_of(small, big):
    return dict(big, **small) == big

def _get_username(id_token_claims):
    return id_token_claims.get(
        "preferred_username",  # AAD
        id_token_claims.get("upn"))  # ADFS 2019

class TokenCache(object):
    """This is considered as a base class containing minimal cache behavior.

    Although it maintains tokens using unified schema across all MSAL libraries,
    this class does not serialize/persist them.
    See subclass :class:`SerializableTokenCache` for details on serialization.
    """

    class CredentialType:
        ACCESS_TOKEN = "AccessToken"
        REFRESH_TOKEN = "RefreshToken"
        ACCOUNT = "Account"  # Not exactly a credential type, but we put it here
        ID_TOKEN = "IdToken"
        APP_METADATA = "AppMetadata"

    class AuthorityType:
        ADFS = "ADFS"
        MSSTS = "MSSTS"  # MSSTS means AAD v2 for both AAD & MSA

    def __init__(self):
        self._lock = threading.RLock()
        self._cache = {}
        self.key_makers = {
            self.CredentialType.REFRESH_TOKEN:
                lambda home_account_id=None, environment=None, client_id=None,
                        target=None, **ignored_payload_from_a_real_token:
                    "-".join([
                        home_account_id or "",
                        environment or "",
                        self.CredentialType.REFRESH_TOKEN,
                        client_id or "",
                        "",  # RT is cross-tenant in AAD
                        target or "",  # raw value could be None if deserialized from other SDK
                        ]).lower(),
            self.CredentialType.ACCESS_TOKEN:
                lambda home_account_id=None, environment=None, client_id=None,
                        realm=None, target=None, **ignored_payload_from_a_real_token:
                    "-".join([
                        home_account_id or "",
                        environment or "",
                        self.CredentialType.ACCESS_TOKEN,
                        client_id or "",
                        realm or "",
                        target or "",
                        ]).lower(),
            self.CredentialType.ID_TOKEN:
                lambda home_account_id=None, environment=None, client_id=None,
                        realm=None, **ignored_payload_from_a_real_token:
                    "-".join([
                        home_account_id or "",
                        environment or "",
                        self.CredentialType.ID_TOKEN,
                        client_id or "",
                        realm or "",
                        ""  # Albeit irrelevant, schema requires an empty scope here
                        ]).lower(),
            self.CredentialType.ACCOUNT:
                lambda home_account_id=None, environment=None, realm=None,
                        **ignored_payload_from_a_real_entry:
                    "-".join([
                        home_account_id or "",
                        environment or "",
                        realm or "",
                        ]).lower(),
            self.CredentialType.APP_METADATA:
                lambda environment=None, client_id=None, **kwargs:
                    "appmetadata-{}-{}".format(environment or "", client_id or ""),
            }

    def _get_access_token(
        self,
        home_account_id, environment, client_id, realm, target,  # Together they form a compound key
        default=None,
    ):  # O(1)
        return self._get(
            self.CredentialType.ACCESS_TOKEN,
            self.key_makers[TokenCache.CredentialType.ACCESS_TOKEN](
                home_account_id=home_account_id,
                environment=environment,
                client_id=client_id,
                realm=realm,
                target=" ".join(target),
                ),
            default=default)

    def _get_app_metadata(self, environment, client_id, default=None):  # O(1)
        return self._get(
            self.CredentialType.APP_METADATA,
            self.key_makers[TokenCache.CredentialType.APP_METADATA](
                environment=environment,
                client_id=client_id,
                ),
            default=default)

    def _get(self, credential_type, key, default=None):  # O(1)
        with self._lock:
            return self._cache.get(credential_type, {}).get(key, default)

    def _find(self, credential_type, target=None, query=None):  # O(n) generator
        """Returns a generator of matching entries.

        It is O(1) for AT hits, and O(n) for other types.
        Note that it holds a lock during the entire search.
        """
        target = sorted(target or [])  # Match the order sorted by add()
        assert isinstance(target, list), "Invalid parameter type"

        preferred_result = None
        if (credential_type == self.CredentialType.ACCESS_TOKEN
            and "home_account_id" in query and "environment" in query
            and "client_id" in query and "realm" in query and target
        ):  # Special case for O(1) AT lookup
            preferred_result = self._get_access_token(
                query["home_account_id"], query["environment"],
                query["client_id"], query["realm"], target)
            if preferred_result:
                yield preferred_result

        target_set = set(target)
        with self._lock:
            # Since the target inside token cache key is (per schema) unsorted,
            # there is no point to attempt an O(1) key-value search here.
            # So we always do an O(n) in-memory search.
            for entry in self._cache.get(credential_type, {}).values():
                if is_subdict_of(query or {}, entry) and (
                        target_set <= set(entry.get("target", "").split())
                        if target else True):
                    if entry != preferred_result:  # Avoid yielding the same entry twice
                        yield entry

    def find(self, credential_type, target=None, query=None):  # Obsolete. Use _find() instead.
        return list(self._find(credential_type, target=target, query=query))

    def add(self, event, now=None):
        """Handle a token obtaining event, and add tokens into cache."""
        def make_clean_copy(dictionary, sensitive_fields):  # Masks sensitive info
            return {
                k: "********" if k in sensitive_fields else v
                for k, v in dictionary.items()
            }
        clean_event = dict(
            event,
            data=make_clean_copy(event.get("data", {}), (
                "password", "client_secret", "refresh_token", "assertion",
            )),
            response=make_clean_copy(event.get("response", {}), (
                "id_token_claims",  # Provided by broker
                "access_token", "refresh_token", "id_token", "username",
            )),
        )
        logger.debug("event=%s", json.dumps(
        # We examined and concluded that this log won't have Log Injection risk,
        # because the event payload is already in JSON so CR/LF will be escaped.
            clean_event,
            indent=4, sort_keys=True,
            default=str,  # assertion is in bytes in Python 3
        ))
        return self.__add(event, now=now)

    def __parse_account(self, response, id_token_claims):
        """Return client_info and home_account_id"""
        if "client_info" in response:  # It happens when client_info and profile are in request
            client_info = json.loads(decode_part(response["client_info"]))
            if "uid" in client_info and "utid" in client_info:
                return client_info, "{uid}.{utid}".format(**client_info)
            # https://github.com/AzureAD/microsoft-authentication-library-for-python/issues/387
        if id_token_claims:  # This would be an end user on ADFS-direct scenario
            sub = id_token_claims["sub"]  # "sub" always exists, per OIDC specs
            return {"uid": sub}, sub
        # client_credentials flow will reach this code path
        return {}, None

    def __add(self, event, now=None):
        # event typically contains: client_id, scope, token_endpoint,
        # response, params, data, grant_type
        environment = realm = None
        if "token_endpoint" in event:
            _, environment, realm = canonicalize(event["token_endpoint"])
        if "environment" in event:  # Always available unless in legacy test cases
            environment = event["environment"]  # Set by application.py
        response = event.get("response", {})
        data = event.get("data", {})
        access_token = response.get("access_token")
        refresh_token = response.get("refresh_token")
        id_token = response.get("id_token")
        id_token_claims = response.get("id_token_claims") or (  # Prefer the claims from broker
            # Only use decode_id_token() when necessary, it contains time-sensitive validation
            decode_id_token(id_token, client_id=event["client_id"]) if id_token else {})
        client_info, home_account_id = self.__parse_account(response, id_token_claims)

        target = ' '.join(sorted(event.get("scope") or []))  # Schema should have required sorting

        with self._lock:
            now = int(time.time() if now is None else now)

            if access_token:
                default_expires_in = (  # https://www.rfc-editor.org/rfc/rfc6749#section-5.1
                    int(response.get("expires_on")) - now  # Some Managed Identity emits this
                    ) if response.get("expires_on") else 600
                expires_in = int(  # AADv1-like endpoint returns a string
                    response.get("expires_in", default_expires_in))
                ext_expires_in = int(  # AADv1-like endpoint returns a string
			response.get("ext_expires_in", expires_in))
                at = {
                    "credential_type": self.CredentialType.ACCESS_TOKEN,
                    "secret": access_token,
                    "home_account_id": home_account_id,
                    "environment": environment,
                    "client_id": event.get("client_id"),
                    "target": target,
                    "realm": realm,
                    "token_type": response.get("token_type", "Bearer"),
                    "cached_at": str(now),  # Schema defines it as a string
                    "expires_on": str(now + expires_in),  # Same here
                    "extended_expires_on": str(now + ext_expires_in)  # Same here
                    }
                if data.get("key_id"):  # It happens in SSH-cert or POP scenario
                    at["key_id"] = data.get("key_id")
                if "refresh_in" in response:
                    refresh_in = response["refresh_in"]  # It is an integer
                    at["refresh_on"] = str(now + refresh_in)  # Schema wants a string
                self.modify(self.CredentialType.ACCESS_TOKEN, at, at)

            if client_info and not event.get("skip_account_creation"):
                account = {
                    "home_account_id": home_account_id,
                    "environment": environment,
                    "realm": realm,
                    "local_account_id": event.get(
                        "_account_id",  # Came from mid-tier code path.
                            # Emperically, it is the oid in AAD or cid in MSA.
                        id_token_claims.get("oid", id_token_claims.get("sub"))),
                    "username": _get_username(id_token_claims)
                        or data.get("username")  # Falls back to ROPC username
                        or event.get("username")  # Falls back to Federated ROPC username
                        or "",  # The schema does not like null
                    "authority_type": event.get(
                        "authority_type",  # Honor caller's choice of authority_type
                        self.AuthorityType.ADFS if realm == "adfs"
                            else self.AuthorityType.MSSTS),
                    # "client_info": response.get("client_info"),  # Optional
                    }
                grant_types_that_establish_an_account = (
                    _GRANT_TYPE_BROKER, "authorization_code", "password",
                    Client.DEVICE_FLOW["GRANT_TYPE"])
                if event.get("grant_type") in grant_types_that_establish_an_account:
                    account["account_source"] = event["grant_type"]
                self.modify(self.CredentialType.ACCOUNT, account, account)

            if id_token:
                idt = {
                    "credential_type": self.CredentialType.ID_TOKEN,
                    "secret": id_token,
                    "home_account_id": home_account_id,
                    "environment": environment,
                    "realm": realm,
                    "client_id": event.get("client_id"),
                    # "authority": "it is optional",
                    }
                self.modify(self.CredentialType.ID_TOKEN, idt, idt)

            if refresh_token:
                rt = {
                    "credential_type": self.CredentialType.REFRESH_TOKEN,
                    "secret": refresh_token,
                    "home_account_id": home_account_id,
                    "environment": environment,
                    "client_id": event.get("client_id"),
                    "target": target,  # Optional per schema though
                    "last_modification_time": str(now),  # Optional. Schema defines it as a string.
                    }
                if "foci" in response:
                    rt["family_id"] = response["foci"]
                self.modify(self.CredentialType.REFRESH_TOKEN, rt, rt)

            app_metadata = {
                "client_id": event.get("client_id"),
                "environment": environment,
                }
            if "foci" in response:
                app_metadata["family_id"] = response.get("foci")
            self.modify(self.CredentialType.APP_METADATA, app_metadata, app_metadata)

    def modify(self, credential_type, old_entry, new_key_value_pairs=None):
        # Modify the specified old_entry with new_key_value_pairs,
        # or remove the old_entry if the new_key_value_pairs is None.

        # This helper exists to consolidate all token add/modify/remove behaviors,
        # so that the sub-classes will have only one method to work on,
        # instead of patching a pair of update_xx() and remove_xx() per type.
        # You can monkeypatch self.key_makers to support more types on-the-fly.
        key = self.key_makers[credential_type](**old_entry)
        with self._lock:
            if new_key_value_pairs:  # Update with them
                entries = self._cache.setdefault(credential_type, {})
                entries[key] = dict(
                    old_entry,  # Do not use entries[key] b/c it might not exist
                    **new_key_value_pairs)
            else:  # Remove old_entry
                self._cache.setdefault(credential_type, {}).pop(key, None)

    def remove_rt(self, rt_item):
        assert rt_item.get("credential_type") == self.CredentialType.REFRESH_TOKEN
        return self.modify(self.CredentialType.REFRESH_TOKEN, rt_item)

    def update_rt(self, rt_item, new_rt):
        assert rt_item.get("credential_type") == self.CredentialType.REFRESH_TOKEN
        return self.modify(self.CredentialType.REFRESH_TOKEN, rt_item, {
            "secret": new_rt,
            "last_modification_time": str(int(time.time())),  # Optional. Schema defines it as a string.
            })

    def remove_at(self, at_item):
        assert at_item.get("credential_type") == self.CredentialType.ACCESS_TOKEN
        return self.modify(self.CredentialType.ACCESS_TOKEN, at_item)

    def remove_idt(self, idt_item):
        assert idt_item.get("credential_type") == self.CredentialType.ID_TOKEN
        return self.modify(self.CredentialType.ID_TOKEN, idt_item)

    def remove_account(self, account_item):
        assert "authority_type" in account_item
        return self.modify(self.CredentialType.ACCOUNT, account_item)


class SerializableTokenCache(TokenCache):
    """This serialization can be a starting point to implement your own persistence.

    This class does NOT actually persist the cache on disk/db/etc..
    Depending on your need,
    the following simple recipe for file-based persistence may be sufficient::

        import os, atexit, msal
        cache = msal.SerializableTokenCache()
        if os.path.exists("my_cache.bin"):
            cache.deserialize(open("my_cache.bin", "r").read())
        atexit.register(lambda:
            open("my_cache.bin", "w").write(cache.serialize())
            # Hint: The following optional line persists only when state changed
            if cache.has_state_changed else None
            )
        app = msal.ClientApplication(..., token_cache=cache)
        ...

    :var bool has_state_changed:
        Indicates whether the cache state in the memory has changed since last
        :func:`~serialize` or :func:`~deserialize` call.
    """
    has_state_changed = False

    def add(self, event, **kwargs):
        super(SerializableTokenCache, self).add(event, **kwargs)
        self.has_state_changed = True

    def modify(self, credential_type, old_entry, new_key_value_pairs=None):
        super(SerializableTokenCache, self).modify(
            credential_type, old_entry, new_key_value_pairs)
        self.has_state_changed = True

    def deserialize(self, state):
        # type: (Optional[str]) -> None
        """Deserialize the cache from a state previously obtained by serialize()"""
        with self._lock:
            self._cache = json.loads(state) if state else {}
            self.has_state_changed = False  # reset

    def serialize(self):
        # type: () -> str
        """Serialize the current cache state into a string."""
        with self._lock:
            self.has_state_changed = False
            return json.dumps(self._cache, indent=4)

