# aupy/idp/self_auth.py

from datetime import datetime
import jwt
import pyodbc
import bcrypt
from .base_auth import BaseAuth

class SelfAuth(BaseAuth):
    def __init__(self, db_connection_string):
        self.db_connection_string = db_connection_string

    def authenticate(self, username, plaintext_password):
        try:
            with pyodbc.connect(self.db_connection_string) as conn:
                cursor = conn.cursor()
                # Recupera l'hash della password dall'utente specifico
                cursor.execute("SELECT * FROM Users WHERE username = ?", (username,))
                user_record = cursor.fetchone()
                
                if user_record:

                    columns = [column[0] for column in cursor.description]
                    password_idx = columns.index('password')  # Trova l'indice della colonna 'password'
                    password_hash = user_record[password_idx]

                    # Usa bcrypt per verificare la corrispondenza delle password
                    if bcrypt.checkpw(plaintext_password.encode('utf-8'), password_hash):
                            columns = [column[0] for column in cursor.description]
                            role_idx = columns.index('role')  # Trova l'indice della colonna 'password'
                            role = user_record[role_idx]

                            user_id = user_record[0]

                            user_data = {
                                'user_id': user_id,
                                'username': username,
                                'role': role
                            }
                            payload = {
                                'sub': user_data,  # 'sub' è un claim standard che indica il soggetto (utente) del token
                                'iat': datetime.datetime.utcnow(),  # 'iat' (Issued At) indica quando è stato emesso il token
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 'exp' (Expiration Time) indica quando il token scadrà
                            }
                            token = jwt.encode(payload, self.secret_key, algorithm='HS256')
                            return token
                return False
        except pyodbc.Error as e:
            print(f"Errore di connessione al database: {e}")
            return False
        
    def create_user(self, username, password,role):
        # Genera un hash sicuro della password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with pyodbc.connect(self.db_connection_string) as conn:
                cursor = conn.cursor()
                # Inserisci l'utente nel database
                # NOTA: Assicurati che la tua tabella e i nomi delle colonne corrispondano a quelli effettivamente utilizzati
                cursor.execute("INSERT INTO Users (username, password,role) VALUES (?, ?)", (username, password_hash,role))
                conn.commit()  # Non dimenticare di eseguire commit delle modifiche
                
                return True
        except pyodbc.Error as e:
            print(f"Errore durante l'inserimento dell'utente nel database: {e}")
            return False
