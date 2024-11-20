from werkzeug.security import generate_password_hash
from app import app, db
from sqlalchemy.sql import text
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
DATABASE_URL = 'sqlite:///trump.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trump.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

def hash_all_user_passwords():
    with app.app_context():
        try:
            # grabs the username and password
            users = db.session.execute(text("SELECT username, password FROM users")).fetchall()

            for user in users:
                user_id = user[0]  # getting the id value
                plain_password = user[1]  # Grabbing the password value

                if plain_password:
                    hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256', salt_length=16) # hashing the password using sha256 and adding salt for extra security

                    # updates the db with the new hashed value
                    update_query = text("UPDATE users SET password = :hashed_password WHERE id = :user_id")
                    db.session.execute(update_query, {"hashed_password": hashed_password, "user_id": user_id})
            db.session.commit()
            print("All passwords have been hashed successfully!")

        except Exception as e:
            db.session.rollback()  # Repeats in case of error
            print(f"An error occurred: {e}")

# Calls the function to hash all user passwords
hash_all_user_passwords()
