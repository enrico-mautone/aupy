# aupy/auth.py

from .idp.proprietary import ProprietaryAuth
from .idp.keycloak import KeycloakAuth
import os

PROPRIETARY_AUTH_TYPE = "PROPRIETARY"
KEYCLOAK_AUTH_TYPE = "KEYCLOAK"
SELF_AUTH_TYPE = "SELF"

class AuthManager:
    # Inizializza il dizionario degli autenticatori con i valori predefiniti
    authenticators = {
        KEYCLOAK_AUTH_TYPE: KeycloakAuth,
        PROPRIETARY_AUTH_TYPE: ProprietaryAuth  # Si suppone che questa sia una classe base astratta
    }

    def __init__(self, **kwargs):
        # Ottiene il tipo di autenticatore dalle variabili di ambiente
        idp_type = os.getenv('IDP_TYPE', SELF_AUTH_TYPE)

        # Recupera la classe autenticatore corrispondente dal dizionario
        AuthenticatorClass = self.authenticators.get(idp_type)

        if not AuthenticatorClass:
            raise ValueError(f"Unsupported IDP type: {idp_type}")

        # Inizializza l'autenticatore
        self.idp = AuthenticatorClass(**kwargs)

    @classmethod
    def register_proprietaty_authenticator(cls, authenticator_class):
        cls.authenticators[PROPRIETARY_AUTH_TYPE] = authenticator_class

    def authenticate(self, username, password):
        return self.idp.authenticate(username, password)
