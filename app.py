import requests

COMMON_PASSWORDS_URL = "https://www.dropbox.com/scl/fi/mssepsyojl2xd8pva1fga/Common_passwords.txt?rlkey=but75iv17emzie71xmbp5tccv&st=kzivm0n4&dl=0"

def download_common_passwords():
  try:
    response = requests.get(COMMON_PASSWORDS_URL)
    response.raise_for_status()    #Raise error for failed requests
    return response.text.splitlines()
  except requests.exceptions.RequestExceptions as e:
    print(f"Error Downloading common_passwords.txt: {e}")
    return[]

Common_passwords = download_common_passwords()
