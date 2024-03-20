from aupy.idp.base import BaseAuth


class KeycloakAuth(BaseAuth):
    def __init__(self, server_url, realm, client_id, client_secret):
        self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret

    def authenticate(self, username, password):
         raise NotImplementedError("Must implement authenticate method")
