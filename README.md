# Installation and Running
1. Make sure you've got Git and Python 3 installed.
2. Clone the project:
  ```
    git clone https://github.com/Hopding/cs4732-project2.git
    cd cs4732-project2
  ```
3. [Install `pipenv`](https://docs.pipenv.org/install/):
  ```
    # For Mac with Homebrew:
    brew install pipenv

    # For Windows or Mac without Homebrew:
    pip install --user pipenv
  ```
4. Install this project's dependencies:
  ```
    pipenv install
  ```
5. Run the sample python script to make sure everything works:
  ```
    pipenv run python main.py
  ```
  It should output the following (with a different key and encrypted message, of course):
  ```
  ##### Demo Script Using "cryptography" Library #####
  Key: b'UtILSrPpQPne-DhbKl_ODfDJFg0bqAtRQrN-xzPY0BQ='

  Encrypted Message: b'gAAAAABbU5DVkU8MV0tAzR1Zuh-kPiGURFkG0ve7HaHbbPp3hiDIEM97fmtxakz9UUyKFU5Hs6Il8EKredW_oZbwGvVUaYQ8bQDZrp9hKOiZXp-CS4gGtnZGyQnXbN9BRcs-wJ02Rpcu'

  Decrypted Message: A really secret message. Not for prying eyes.
  ```
# pr2_t4
