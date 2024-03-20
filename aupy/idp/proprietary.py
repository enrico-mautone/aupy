from aupy.idp.base import BaseAuth


class ProprietaryAuth(BaseAuth):
    def authenticate(self, username, password):
        raise NotImplementedError("Must implement authenticate method")
