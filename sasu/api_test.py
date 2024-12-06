import requests

def fetch_users():
    url = 'http://127.0.0.1:8000/api/chain'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return []

# Menggunakan fungsi
users = fetch_users()
for user in users:
    print(f"Name: {user['name']}, Email: {user['email']}")