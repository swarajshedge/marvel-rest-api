# REST-API-Marvel

### Project Description : This is a project that involved the creation of a REST API from scratch for the purpose of performing ETL operations on Marvel Database.

This project has 2 main parts. 

## PART-1 : Marvel API Character Stats

This Python project interacts with the **Marvel API** to retrieve information on a list of 30 random Marvel characters. **The program uses the public and private keys to make API requests and retrieves the total number of events, series, and comics for each character**. Additionally, the code retrieves the price of the most expensive comic for each character by making a request to the ```/characters/{characterID}/comics``` endpoint.

The program outputs the retrieved data into a Pandas dataframe and saves it as a CSV file. The program replaces any 0 values with the None datatype for better data representation.


## PART-2 : Flask REST API 

This Python project is a Flask API that allows users to sign up, log in, search, modify & delete the information of Marvel characters. This API interacts with the Marvel character database that has been created in the PART-1 of this project. The API has three main endpoints, namely **```signup```**, **```login```**, and **```characters```**.

The **SignUp** resource associated with the **```signup```** endpoint, allows users to sign up by submitting their email and password. If the email already exists in the user database, the API returns an error message; otherwise, the API adds the email and a hashed password to the database and returns a success message.

The **LogIn** resource associated with the **```login```** endpoint, allows users to log in by submitting their email and password. If the email does not exist in the database, the API returns an error message; otherwise, the API checks the submitted password against the hashed password in the database. If the passwords match, the API generates a **JSON Web Token (JWT)** for the user, which is valid for one hour, and returns a success message containing the token.

The **Characters** resource associated with the **```characters```** endpoint, allows users to perform multiple ETL processes. 
- **GET** : Retrieves information for a single entry or for a list of entries identified by either the Character Name or the Character ID.
- **POST** : Adds a new character to the existing database by specifying its characteristics (Character Name, Character ID, Available Events, Available Series, Available Comics, and Price of Comic). The API restricts addition of characters with pre-existing Character IDs.
- **DELETE** : Adds a new character to the existing databse by specifying only the Character ID. The API fills in the remaining information by extracting it from Marvel's API and appends to the databse. The API returns an error if the provided character id is not found in the databse.
- **PUT** : Deletes a character or a list of characters by providing either the Character ID or the Character Name. The API returns an error if the character you are trying to delete does not exist in the database.

### Important Note 
The detailed documentation corresponding to all the ETL processes for the API are present in the **```API_documentation.ipynb```** file.

## Requirements
- Python 3
- Pandas
- Requests
- Hashlib
- tqdm
- Flask
- flask_jwt_extended
- flask_bcrypt
- flask_restful

## Usage
- Clone the repository
- For PART-1, replace the public_key and private_key variables with your **own Marvel API keys**.
- Run the Python script and wait for it to complete
- A file named ```data.csv``` will be created in the same directory as the script.
- For PART-2, start a simple Flask server in your local machine or remotely (maybe in an AWS EC2 instance). 
- Create a set of login credentials and follow the documentation to perform ETL operations using the API (Refer the API documentation file for more details).
