from abc import ABC, abstractmethod

class BaseAuth(ABC):
    def __init__(self, **kwargs):
        super().__init__()

    @abstractmethod
    def authenticate(self, username, password):
        pass
