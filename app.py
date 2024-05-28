import streamlit as st
import pandas as pd
from datetime import datetime
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib  
# Setup basic configuration for logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Define paths for CSV files
ACCOUNTS_FILE = 'accounts.csv'
TRANSACTIONS_FILE = 'transactions.csv'
USERS_FILE = 'users.csv'
SERVICES_FILE = 'services.csv'
RECURRING_FILE = 'recurring.csv'

# Helper functions for CSV operations
def load_data(file_path, columns):
    try:
        return pd.read_csv(file_path, index_col=0)
    except FileNotFoundError:
        logging.error(f"{file_path} not found, creating new dataframe.")
        return pd.DataFrame(columns=columns)

def save_data(df, file_path):
    try:
        df.to_csv(file_path)
    except Exception as e:
        logging.error(f"Failed to save data to {file_path}: {str(e)}")

# Security and encryption functions
def get_key(password):
    salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=32)  # Generates a 256-bit key
    return key, salt

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(key, encrypted_message):
    try:
        b64 = base64.b64decode(encrypted_message)
        nonce, tag, ciphertext = b64[:16], b64[16:32], b64[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except (ValueError, KeyError):
        return False

def hash_password(password):
    salt = os.urandom(16)  # Generate a new salt
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    salted_hash = salt + pwd_hash
    return base64.b64encode(salted_hash).decode()  # Store the salt and hash as a single encoded string

def check_password(stored_password, provided_password):
    decoded = base64.b64decode(stored_password)
    salt = decoded[:16]  # The first 16 bytes are the salt
    stored_hash = decoded[16:]  # The rest is the hash
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return new_hash == stored_hash


# Load dataframes
accounts_df = load_data(ACCOUNTS_FILE, ['Account Number', 'Name', 'Account Type', 'Balance'])
transactions_df = load_data(TRANSACTIONS_FILE, ['Date', 'Type', 'From', 'To', 'Amount'])
users_df = load_data(USERS_FILE, ['Username', 'Password'])
services_df = load_data(SERVICES_FILE, ['Account Number', 'Service Type', 'Status'])
recurring_df = load_data(RECURRING_FILE, ['Account Number', 'Payment Type', 'Amount', 'Frequency', 'Next Due'])
# Authentication functions
def register_user(username, password):
    if username in users_df['Username'].values:
        st.error("Username already exists.")
    else:
        encrypted_password = hash_password(password)
        users_df.loc[len(users_df) + 1] = [username, encrypted_password]
        save_data(users_df, USERS_FILE)
        st.success("User registered successfully!")

def login_user(username, password):
    user_record = users_df[users_df['Username'] == username]
    if not user_record.empty and check_password(user_record.iloc[0]['Password'], password):
        st.session_state['logged_in'] = True
        st.session_state['user'] = username
        logging.info(f"User {username} logged in.")
        return True
    else:
        return False

def show_login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        if login_user(username, password):
            st.success("Logged in successfully.")
            st.experimental_rerun()
        else:
            st.error("Incorrect username or password.")

def show_registration():
    st.subheader("Register")
    username = st.text_input("Choose a Username", key="reg_username")
    password = st.text_input("Set a Password", type="password", key="reg_password")
    if st.button("Register"):
        register_user(username, password)

def create_account():
    st.subheader('Create New Account')
    name = st.text_input('Enter Your Name', key="new_name")
    account_type = st.radio("Select Account Type", ('Personal', 'Business'), key="new_type")
    balance = st.number_input('Initial Balance', value=0.0, step=0.01, format="%.2f", key="new_balance")
    if st.button('Create Account'):
        new_account_number = len(accounts_df) + 1
        accounts_df.loc[new_account_number] = [new_account_number, name, account_type, balance]
        save_data(accounts_df, ACCOUNTS_FILE)
        st.success(f'Account created successfully! Account Number: {new_account_number}')

def edit_account_details():
    st.subheader('Edit Account Details')
    account_number = st.number_input('Enter Account Number to Edit', format="%.2f")
    if account_number in accounts_df.index:
        with st.form("Edit Form"):
            name = st.text_input('Name', value=accounts_df.at[account_number, 'Name'])
            account_type = st.radio("Account Type", ('Personal', 'Business'))
            submit = st.form_submit_button("Save Changes")
            if submit:
                accounts_df.at[account_number, 'Name'] = name
                accounts_df.at[account_number, 'Account Type'] = account_type
                save_data(accounts_df, ACCOUNTS_FILE)
                st.success('Account updated successfully!')

def close_account():
    global accounts_df
    st.subheader('Close Account')
    account_number = st.number_input('Enter Account Number to Close', format="%.2f")
    if st.button('Close Account'):
        if account_number in accounts_df.index:
            accounts_df = accounts_df.drop(account_number)
            save_data(accounts_df, ACCOUNTS_FILE)
            st.success('Account closed successfully!')
        else:
            st.error('Account not found!')

def deposit_cash():
    st.subheader('Deposit Cash')
    account_number = st.number_input('Enter Account Number', format="%.2f")
    amount = st.number_input('Enter Amount', step=0.01, format="%.2f")
    if st.button('Deposit') and account_number and amount > 0:
        if account_number in accounts_df.index:
            accounts_df.loc[account_number, 'Balance'] += amount
            transaction_record = {'Date': datetime.now().isoformat(), 'Type': 'Deposit', 'From': None, 'To': account_number, 'Amount': amount}
            transactions_df.loc[len(transactions_df) + 1] = transaction_record
            save_data(accounts_df, ACCOUNTS_FILE)
            save_data(transactions_df, TRANSACTIONS_FILE)
            st.success('Deposit successful!')
            logging.info(f"Deposit of {amount} to account {account_number}.")

def withdraw_cash():
    st.subheader('Withdraw Cash')
    account_number = st.number_input('Enter Account Number', format="%.2f")
    amount = st.number_input('Enter Amount', step=0.01, format="%.2f")
    if st.button('Withdraw') and account_number and amount > 0:
        if account_number in accounts_df.index and accounts_df.loc[account_number, 'Balance'] >= amount:
            accounts_df.loc[account_number, 'Balance'] -= amount
            transaction_record = {'Date': datetime.now().isoformat(), 'Type': 'Withdrawal', 'From': account_number, 'To': None, 'Amount': amount}
            transactions_df.loc[len(transactions_df) + 1] = transaction_record
            save_data(accounts_df, ACCOUNTS_FILE)
            save_data(transactions_df, TRANSACTIONS_FILE)
            st.success('Withdrawal successful!')
            logging.info(f"Withdrawal of {amount} from account {account_number}.")

def transfer_funds():
    st.subheader('Transfer Funds')
    from_account = st.number_input('Enter Account Number to Transfer From', format="%.2f")
    to_account = st.number_input('Enter Account Number to Transfer To', format="%.2f")
    amount = st.number_input('Enter Amount', step=0.01, format="%.2f")
    if st.button('Transfer') and from_account and to_account and amount > 0:
        if from_account in accounts_df.index and to_account in accounts_df.index:
            if accounts_df.loc[from_account, 'Balance'] >= amount:
                accounts_df.loc[from_account, 'Balance'] -= amount
                accounts_df.loc[to_account, 'Balance'] += amount
                transaction_record = {'Date': datetime.now().isoformat(), 'Type': 'Transfer', 'From': from_account, 'To': to_account, 'Amount': amount}
                transactions_df.loc[len(transactions_df) + 1] = transaction_record
                save_data(accounts_df, ACCOUNTS_FILE)
                save_data(transactions_df, TRANSACTIONS_FILE)
                st.success('Transfer successful!')
                logging.info(f"Transfer of {amount} from {from_account} to {to_account}.")
            else:
                st.error('Insufficient balance!')
                logging.warning(f"Failed transfer of {amount} from {from_account} to {to_account} due to insufficient balance.")
        else:
            st.error('One or both accounts not found!')
            logging.warning(f"Transfer attempt failed from {from_account} to {to_account}: One or both accounts not found.")

def view_account_info():
    st.subheader('View Account Information')
    account_number = st.number_input('Enter Account Number', format="%.2f")
    if st.button('View Info') and account_number:
        if account_number in accounts_df.index:
            account_info = accounts_df.loc[account_number]
            st.write('**Account Number:**', account_info['Account Number'])
            st.write('**Name:**', account_info['Name'])
            st.write('**Account Type:**', account_info['Account Type'])
            st.write('**Balance:**', account_info['Balance'])
            logging.info(f"Viewed account info for {account_number}.")
        else:
            st.error('Account not found!')
            logging.warning(f"Attempted to view non-existing account {account_number}.")

def manage_services():
    st.subheader("Request and Manage Services")
    account_number = st.number_input('Enter Your Account Number', format="%.2f")
    service_type = st.selectbox('Select Service', ['Checkbook', 'Debit Card', 'Credit Card'])
    if st.button('Request Service'):
        services_df.loc[len(services_df) + 1] = [account_number, service_type, 'Requested']
        save_data(services_df, SERVICES_FILE)
        st.success(f'{service_type} requested successfully!')

def setup_recurring_payments():
    st.subheader("Setup and Manage Recurring Payments")
    account_number = st.number_input('Enter Your Account Number', format="%.2f")
    payment_type = st.text_input('Payment Description')
    amount = st.number_input('Payment Amount', min_value=0.01, step=0.01, format="%.2f")
    frequency = st.selectbox('Select Frequency', ['Monthly', 'Quarterly', 'Annually'])
    next_due = st.date_input('Next Due Date')
    if st.button('Setup Payment'):
        recurring_df.loc[len(recurring_df) + 1] = [account_number, payment_type, amount, frequency, next_due]
        save_data(recurring_df, RECURRING_FILE)
        st.success('Recurring payment setup successfully!')

# Main function to run the Streamlit app
def main():
    st.title('Advanced Banking Application')
    if 'logged_in' not in st.session_state:
        auth_choice = st.sidebar.selectbox('Authentication', ['Login', 'Register'])
        if auth_choice == 'Login':
            show_login()
        elif auth_choice == 'Register':
            show_registration()
    else:
        menu = ['Create Account', 'Edit Account Details', 'Close Account', 'Deposit Cash', 'Withdraw Cash', 'Transfer Funds', 'View Account Information', 'Manage Services', 'Setup Recurring Payments']
        choice = st.sidebar.selectbox('Select Option', menu)
        if choice == 'Create Account':
            create_account()
        elif choice == 'Edit Account Details':
            edit_account_details()
        elif choice == 'Close Account':
            close_account()
        elif choice == 'Deposit Cash':
            deposit_cash()
        elif choice == 'Withdraw Cash':
            withdraw_cash()
        elif choice == 'Transfer Funds':
            transfer_funds()
        elif choice == 'View Account Information':
            view_account_info()
        elif choice == 'Manage Services':
            manage_services()
        elif choice == 'Setup Recurring Payments':
            setup_recurring_payments()

if __name__ == "__main__":
    main()
