from flask_login import UserMixin
from flask import session

class User(UserMixin):
    def __init__(self, email, senha_hash):
        self.email = email
        self.senha = senha_hash
        self.id = email  # Usado pelo Flask-Login

    @classmethod
    def get(cls, user_id):
        usuarios = session.get('usuarios', {})
        if user_id in usuarios:
            return cls(user_id, usuarios[user_id])
        return None
