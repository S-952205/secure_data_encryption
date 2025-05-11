import streamlit as st
import hashlib
from cryptography.fernet import Fernet # data encryption or decryption kayliye 


# yeh humnay key generate kee jiskee help say hum encryption or dcryption krein gay.
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key() # key session state main siliye rakhee hai takay rerun pay new key na generate hoo
    
cipher = Fernet(st.session_state.key)

# KEY = Fernet.generate_key()
# cipher = Fernet(KEY) # yahan humnay object banaya or yeh object key kee help say encrypt dcrypt krayga.

# App shuru hone par sab initialize karein  
if 'stored_data' not in st.session_state:  
    st.session_state.stored_data = {}  

# st.session_state app ke sab functions aur pages mein accessible hai bina global declare kiye.
if 'failed_attempts' not in st.session_state:  
    st.session_state.failed_attempts = 0 

if 'current_page' not in st.session_state:  
    st.session_state.current_page = "Home" 


# stored_data: dict = {}     # yeh dictioary encrypted data or hashed passkey store kray gee
# failed_attempts: int = 0   # galat attempts count karne ke liye kitni baar galat password diya gaya hai, ye track karega


# yeh function humaray password ko hashed pass main convert kray ga hum password original form main nhi store krtay
# hamesha hashed krkay store krtay hain.
def hash_passkey(passkey):
    """Convert passkey to SHA-256 hash"""
    return hashlib.sha256(passkey.encode()).hexdigest() # encode say byte main convert horaha phir sha256 say hashed horaha


def encrypt_data(data, passkey):   
    """Encrypt data using Fernet encryption"""
    return cipher.encrypt(data.encode()).decode()


def decrypt_data(encrypted_txt, passkey):
    """Decrypt data if passkey matches"""

    st.session_state.failed_attempts 
    hashed_passkey = hash_passkey(passkey)

    # key kay under key or value main nested dictionary ai stored_data.items say key, values miltein
    # hum dekhrahay jo dictionary main stored encrypted data or hashed pass key hain woo user kay diye gai
    # encrypted data or hashed pass key say match krta hai kay nhi agr krta hai tw failed attempts = 0 agr nhi krta
    # tw failed attempts += 1 hojaiga.
    for key, value in st.session_state.stored_data.items():
        if value['encrypted_data'] == encrypted_txt and value['hashed_pass'] == hashed_passkey:
            st.session_state.failed_attempts = 0
                                    # data decrypt horaha or original foam main recieve hojaiga
            return cipher.decrypt(encrypted_txt.encode()).decode() 
        
    st.session_state.failed_attempts += 1
    return None
    


# streamlit work starts from here
st.title('🔒 Secure Data Encryption System') # simple title display

# navigation sidebar main
# menu: list = ['Home', 'Store Data', 'Retrieve Data', 'Login']
# choice = st.sidebar.selectbox('Navigation', menu)


# index Parameter automatically select kar raha hai correct option
choice = st.sidebar.selectbox(  
    "Navigation",  
    ["Home", "Store Data", "Retrieve Data", "Login"],  
    index=["Home", "Store Data", "Retrieve Data", "Login"].index(st.session_state.current_page)  
)  

if choice == 'Home':
    st.session_state.current_page = 'Home'
    

    st.subheader('🏠 Welcome to the Secure Data System')
    st.write('Use this app to **securely store and retrieve data** using unique passkeys.')


elif choice == 'Store Data':
    st.session_state.current_page = 'Store Data'
    st.write(f'This is current page: {st.session_state.current_page}')

    st.subheader('📂 Store Data Securely')

    user_data = st.text_area('Enter Data: ')
    user_passkey = st.text_input('Enter Passkey: ', type='password')

    if st.button('Encrypt and Save'):

        if user_data and user_passkey:

            encrypted_data = encrypt_data(user_data, user_passkey)
            hashed_passkey = hash_passkey(user_passkey)

            # Session State ka Role: Ye data app refresh ya navigation ke baad bhi survive karega reset nhi hoga.
            st.session_state.stored_data['user_secret'] ={'encrypted_data': encrypted_data, 'hashed_pass': hashed_passkey}
            st.success('✅ Data stored securely!')
            st.write(encrypted_data)

        else:
            st.error('⚠ Both fields are required!')



elif choice == 'Retrieve Data':
    st.session_state.current_page = 'Retrieve Data'
    st.write(f'This is current page: {st.session_state.current_page}')
    encrypt_to_decrypt = st.text_area('Enter Encrypted Data: ')
    user_passkey = st.text_input('Enter Passkey: ', type='password')

    if st.button('Decrypt'):
        if encrypt_to_decrypt and user_passkey:
            decrypted_data =  decrypt_data(encrypt_to_decrypt, user_passkey)

            if decrypted_data:
                st.success(f'Decrypted Data: {decrypted_data}')
            else:
                st.error(f'❌ Incorrect Passkey! Attempt remaining {3 - st.session_state.failed_attempts}')

                if st.session_state.failed_attempts >= 3:
                    st.warning('Too many failed attempts! Redirecting to Login Page.')
                    st.session_state.current_page = 'Login'
                    st.rerun()
        
        else:
            st.error("⚠️ Both fields are required!")


elif choice == 'Login':
    st.session_state.current_page = 'Login'
    st.write(f'This is current page: {st.session_state.current_page}')
    st.subheader('🔑 Reauthorization Required')
    login_pass = st.text_input('Enter Master Pass: ', type='password')

    if st.button('Login'):
        if login_pass == 'syedali010':
             st.session_state.failed_attempts = 0
             st.success('✅ Reuthorized Successfully! Redirecting to Retrieve Data...')
             st.session_state.current_page = 'Retrieve Data'

             # rerun pay selectbox ka index change ho raha hai Selectbox automatically 3rd option ("Retrieve Data") select karega
             st.rerun() 
        else:
            st.error('❌ Incorrect Password!')

    

# Har Interaction ke baad: Streamlit poori script dobara chalata hai, lekin session state values preserve rehti hain
# st.session_state variables app ke lifetime tak survive karte hain (jab tak browser band nahi hota)
# Agar aapke app mein multiple pages hain aur aap data ko un pages ke beech share karna chahte hain.
# user kay input ko remember rakhna hai tw session state use karein
# cipher ko session state mein rakhnay se encryption/decryption ke liye same key use hoti hai




