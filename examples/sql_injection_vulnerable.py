"""
Example: SQL Injection Vulnerability
This code demonstrates a classic SQL injection vulnerability
"""

import sqlite3


class UserDatabase:
    def __init__(self, db_path="users.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        """Initialize database"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        self.conn.commit()

    def authenticate_user(self, username, password):
        """
        VULNERABLE: SQL Injection vulnerability
        User input is directly concatenated into SQL query
        """
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result is not None

    def get_user_by_id(self, user_id):
        """
        VULNERABLE: SQL Injection via user_id parameter
        """
        query = "SELECT * FROM users WHERE id = " + str(user_id)
        self.cursor.execute(query)
        return self.cursor.fetchone()

    def search_users(self, search_term):
        """
        VULNERABLE: SQL Injection in LIKE clause
        """
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def update_email(self, user_id, new_email):
        """
        VULNERABLE: SQL Injection in UPDATE statement
        """
        query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
        self.cursor.execute(query)
        self.conn.commit()


# Example exploitation scenarios:
if __name__ == "__main__":
    db = UserDatabase()

    # Attack 1: Authentication bypass
    # Input: username = "admin' OR '1'='1", password = "anything"
    # Resulting query: SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'
    # This always returns true, bypassing authentication

    # Attack 2: Data extraction
    # Input: user_id = "1 UNION SELECT username, password, NULL, NULL, NULL FROM users"
    # This can extract all usernames and passwords

    # Attack 3: SQL injection in search
    # Input: search_term = "' OR 1=1 --"
    # This returns all users

    print("WARNING: This code contains intentional SQL injection vulnerabilities!")
    print("For educational purposes only!")
