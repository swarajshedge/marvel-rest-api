##INSTALLING THE forex-python LIBRARY WHICH IS USED IN THE BONUS PART##
import subprocess
import sys
subprocess.check_call([sys.executable, "-m", "pip", "install", "forex-python"])

#IMPORTING ALL THE REQUIRED LIBRARIES 
import datetime
import requests
import hashlib
import time
import pandas as pd
from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token
from forex_python.converter import CurrencyRates

app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app) # Set up the Bcrypt extension
jwt = JWTManager(app) # Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "Valar-Morghulis" 

def hash_password(password):
        return generate_password_hash(password).decode('utf8')
    

## START OF SIGNUP RESOURCE ##   
class SignUp(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, help='Missing argument email', required=True, location='args')
        parser.add_argument('password', type=str, help='Missing argument password', required=True, location='args')
        args = parser.parse_args()  # parse arguments to dictionary

        # read our CSV
        df = pd.read_csv('users.csv')
        
        if args['email'] in list(df['email']):
            return {'status': 409, 'response': args['email']+' already exists!'}, 409
        else:
            df.loc[len(df)]=[args['email'], hash_password(args['password'])]
            df.to_csv('users.csv', index=False)  # save back to CSV
            return {'status': 200, 'response': 'Successfully signed up'}, 200 # return data and 200 OK
## END OF SIGNUP RESOURCE ##
        
        

    
## START OF LOGIN RESOURCE ##    
class LogIn(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, help='Missing argument email', required=True,location='args')
        parser.add_argument('password', type=str, help='Missing argument password', required=True,location='args')
        args = parser.parse_args()  # parse arguments to dictionary

        # read our CSV
        df = pd.read_csv('users.csv')
        
        if args['email'] not in list(df['email']):
            return {'status': 401, 'response': 'Invalid email'}, 401
        else: 
            
            # look for password hash in database
            password= list(df["password"])[df[df["email"]==args['email']].index[0]]      
            
            if check_password_hash(password, args['password']):
                expires = datetime.timedelta(hours=1)
                access_token = create_access_token(identity=str(df.loc[df['email']==args['email']].index[0]), 
                                                   expires_delta=expires)
                return {'status': 200, 'response': 'Successfully logged in', 'token': access_token}, 200
            else:
                return {'status': 401, 'response': 'Invalid password!'}, 401
## END OF LOGIN RESOURCE ##


        
## START OF CHARACTERS RESOURCE ##        
class Characters(Resource):
    
    ##START OF GET##
    def get(self):
        #Defining arguments 
        parser = reqparse.RequestParser()  
        parser.add_argument('Character Name', type=str, action='append', required=False, location='args')
        parser.add_argument('Character ID', type=str, action='append', required=False, location='args')
        args = parser.parse_args()      #Parsing arguments to dictionary
        
        #Renaming the arguments for readability
        a1=args['Character Name']
        a2=args['Character ID']
        
        #Reading data from the csv file
        df = pd.read_csv('data.csv')
        
        if (a1 is None) & (a2 is None):     #When no parameters are passed -> returns the entire dataframe
            return {'status': 200, 'response': df.to_dict(orient='records')}, 200
        
        elif (a1 is not None) & (a2 is None) :           #When the user passes list of Character Names
            
            if len(set(a1) & set(list(df['Character Name'])))>0:     #checking if list of Names is present in dataframe
                char_list = list(set(a1) & set(list(df['Character Name'])))  
                entry=df[df["Character Name"].isin(char_list)].to_dict(orient='records')  #getting the data for the required names          
                return {'status': 200, 'response': entry}, 200
            
            else :
                return {'status': 404, 'response': "Character not found!"}, 404
            
        elif (a1 is None) & (a2 is not None) :           #When the user passes list of Character IDs
            
            test=list(df['Character ID'])                
            test = list(map(str, test))                  #typecasting all the elements of the character ID list into strings
            
            if len(set(a2) & set(test))>0:               #checking if list of IDs is present in dataframe
                char_list_id=list(map(int,list(set(a2) & set(test))))
                entry=df[df["Character ID"].isin(char_list_id)]      #getting the data for the required IDs         
                return {'status': 200, 'response': entry.to_dict(orient='records')}, 200
            else :
                return {'status': 404, 'response': "Character not found!"}, 404
            
        else:                     
            return {'status': 402, 'response': "Too many parameters!"}, 402      
    ##END OF GET##
    
    
    
    ##START OF POST##
    #USER NEEDS TO PROVIDE AUTHENTICATION##
    @jwt_required()    
    def post(self):
        #Defining arguments 
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, help="token is required", required=True, location='headers')
        parser.add_argument('Character Name', type=str, required=False, location='args')  
        parser.add_argument('Character ID', type=str, required=False, location='args')
        parser.add_argument('Total Available Events', type=int, required=False, location='args')
        parser.add_argument('Total Available Series', type=int, required=False, location='args')
        parser.add_argument('Total Available Comics', type=int, required=False, location='args')
        parser.add_argument('Price of the Most Expensive Comic', type=float, required=False, location='args')
        args = parser.parse_args()      #Parsing arguments to dictionary
        
        
        #Renaming the arguments for readability
        a1=args['Character Name']
        a2=args['Character ID']
        a3=args['Total Available Events']
        a4=args['Total Available Series']
        a5=args['Total Available Comics']
        a6=args['Price of the Most Expensive Comic']
        
        #When the user provides all the 6 parameters
        if ((a1 is not None)&(a2 is not None)&(a3 is not None)&(a4 is not None)&(a5 is not None)&(a6 is not None)):
            
            df = pd.read_csv('data.csv')                  #Reading data from the csv file
            test=list(df['Character ID'])
            test = list(map(str, test))                   #typecasting all the elements of the character ID list into strings
             
            if a2 in test:                                #checking if the ID is already present in dataframe
                return {'status': 403, 'response': "Character already present!"}, 403
            
            else :
                df.loc[len(df)]=[args['Character Name'],args['Character ID'],args['Total Available Events'],
                                 args['Total Available Series'],args['Total Available Comics'],
                                 args['Price of the Most Expensive Comic']]   #appending the new row to the dataframe
                df.to_csv("data.csv",index=False)                             # saving to CSV 
                return {'status': 200, 'response': "Record added successfully!"}, 200 
        
        
        #When the user provides only the Character ID
        elif ((a1 is None)&(a2 is not None)&(a3 is None)&(a4 is None)&(a5 is None)&(a6 is None)):
             
            df = pd.read_csv('data.csv')                  #Reading data from the csv file
            test=list(df['Character ID'])   
            test = list(map(str, test))                   #typecasting all the elements of the character ID list into strings
            if a2 in test:                                #checking if the ID is already present in dataframe
                return {'status': 403, 'response': "Character already present!"}, 403
            
            else:
                ##INTERACTING WITH THE MARVEL API##
                pub="4bebeccc9012020c0a09bdc583b47333"              #public key for interacting with marvel API
                priv="4cfa7defe2de1b8f7de41bf7363c9c217dee3d62"     #private key for interacting with marvel API     
                base_url_1="https://gateway.marvel.com:443/v1/public/"
                base_url_2="?ts="
                ts=time.time()                                      #current timestamp
                base_url_3="&apikey="
                base_url_4="&hash="
                auth=str(ts)+priv+pub
                auth_hash= hashlib.md5(auth.encode()).hexdigest()   #getting hexadecimal hash

                
                #This url is used to get the name, total events, series and comics for the given character ID
                url_1=base_url_1+"characters/"+ a2 + base_url_2 + str(ts) + base_url_3 + pub + base_url_4 + str(auth_hash)
                response1=requests.get(url_1,{"characterId":int(a2)}).json()
                
                if response1['code']==404:                         #checking if the character is present in marvel database!
                    return {'status': 404, 'response': "Character not found!"}, 404
                
                else:
                    post1=response1["data"]["results"][0]["name"]
                    post2=a2
                    post3=response1["data"]["results"][0]["events"]["available"]
                    post4=response1["data"]["results"][0]["series"]["available"]
                    post5=response1["data"]["results"][0]["comics"]["available"]
                    
                    #This url is used to get the prices data for the comics in which the character appears!
                    url_2=base_url_1+"characters/"+a2+"/comics"+base_url_2+str(ts)+base_url_3+pub+base_url_4+str(auth_hash)
                    response2=requests.get(url_2,{"limit":100,"characterId":int(a2)}).json()
                    
                    if post5<=100:       #if the character has appeared in less than 100 comics
                        post6=float(max(response2["data"]["results"][i]["prices"][0]["price"] for i in range(post5)))
                    else:                #if the character has appeared in more than 100 comics
                        post6=float(max(response2["data"]["results"][i]["prices"][0]["price"] for i in range(100)))

                    df.loc[len(df)]=[post1,post2,post3,post4,post5,post6]     #appending the new row to the dataframe
                    
                    df=df.replace(0, None)                                    #Replacing the 0s with None datatype
                    
                    df.to_csv("data.csv",index=False)                         # saving to CSV 
                    return {'status': 200, 'response': "Record appended successfully"}, 200
                    
        else : 
            return {'status': 400, 'response': "Parameters provided incorrectly!"}, 400 
    ##END OF POST##
    
    
   
    ##START OF DELETE##
    #USER NEEDS TO PROVIDE AUTHENTICATION##
    @jwt_required()
    def delete(self):
        #Defining arguments 
        parser = reqparse.RequestParser()
        parser.add_argument('Authorization', type=str, help="token is required", required=True, location='headers')
        parser.add_argument('Character Name', type=str, action='append',help="Missing argument", required=False,location='args')  
        parser.add_argument('Character ID', type=str, action='append',help="Missing argument", required=False,location='args')
        args = parser.parse_args()      #Parsing arguments to dictionary
        
        
        #Renaming the arguments for readability
        a1=args['Character Name']
        a2=args['Character ID']
        
        #Reading data from the csv file
        df = pd.read_csv('data.csv')
        
        if ((a1 is None)&(a2 is None)):              #When no parameters are passed -> throws in an error
            return {'status': 403, 'response': "Parameters provided incorrectly"}, 400
        
        elif ((a1 is not None)&(a2 is None)):        #When the user passes list of Character Names
            
            if len(set(a1) & set(list(df['Character Name'])))>0:       #checking if list of Names is present in dataframe
                
                char_list=list(set(a1) & set(list(df['Character Name'])))
                df=df[~df["Character Name"].isin(char_list)]           #unselecting the required rows from the dataframe
                df.to_csv("data.csv",index=False)                      # saving to CSV 
                return {'status': 200, 'response': "Records deleted successfully"}, 200
            
            else :
                
                return {'status': 404, 'response': "Character not found!"}, 404  
            
        elif ((a1 is None)&(a2 is not None)):        #When the user passes list of Character IDs
            
            test=list(df['Character ID'])         
            test = list(map(str, test))              #typecasting all the elements of the character ID list into strings

            if len(set(a2) & set(test))>0:           #checking if list of IDs is present in datafframe
                
                char_list_id=list(map(int,list(set(a2) & set(test))))
                df=df[~df["Character ID"].isin(char_list_id)]          #unselecting the required rows from the dataframe 
                df.to_csv("data.csv",index=False)                      # saving to CSV 
                return {'status': 200, 'response': "Records deleted successfully"}, 200
            
            else :
                
                return {'status': 404, 'response': "Character not found!"}, 404
            
        else:
            return {'status': 402, 'response': "Too many parameters!"}, 402        
    ##END OF DELETE##
    
    
    
    ##START OF PUT##
    #USER NEEDS TO PROVIDE AUTHENTICATION##
    @jwt_required()
    def put(self):
        #Defining arguments 
        parser = reqparse.RequestParser()  
        parser.add_argument('Authorization', type=str, help="token is required", required=True, location='headers')
        parser.add_argument('Character Name', type=str, required=False,location='args')
        parser.add_argument('Character ID', type=str, required=False,location='args')
        parser.add_argument('currency', type=str, required=False,location='args')
        parser.add_argument('new_price', type=float, required=False,location='args')
        args = parser.parse_args()      #Parsing arguments to dictionary  
        
        #Renaming the arguments for readability
        a1=args['Character Name']
        a2=args['Character ID']
        a3=args['currency']
        a4=args['new_price']
        
        df = pd.read_csv('data.csv')        #Reading data from the csv file
        
        if (a1 is None) & (a2 is None):     #When both Character Name and Character ID are not passed
            return {'status': 400, 'response': "Parameters provided incorrectly"}, 400
         
        elif (a1 is not None) & (a2 is None):                     #When the user passes Character Name
            
            if (a1 in list(df['Character Name'])) :               #checking if the Name is present in dataframe
                
                if a3 in ["USD","EUR","GBP","CAD"]:               #checking if the currency is in acceptable formats
                    exc=CurrencyRates().get_rate(a3, 'USD')       #evaluating the realtime exhcange rate 
                    df.loc[df["Character Name"]==a1,["Price of the Most Expensive Comic"]]=round(float(a4*exc),2)
                    df.to_csv("data.csv",index=False)
                    entry=df[df["Character Name"]==a1].to_dict(orient='records')
                    return {'status': 200, 'response': entry}, 200
                
                else:
                    return {'status': 405, 'response': "Currency not acceptable!"}, 405
                
            else:
                return {'status': 404, 'response': "Character not found!"}, 404
            
        elif (a1 is None) & (a2 is not None) :       #When the user passes Character ID
            
            test=list(df['Character ID'])
            test = list(map(str, test))              #typecasting all the elements of the character ID list into strings
            if a2 in test :                          #checking if the ID is present in dataframe
                
                if a3 in ["USD","EUR","GBP","CAD"]:               #checking if the currency is in acceptable formats
                    
                    exc=CurrencyRates().get_rate(a3, 'USD')       #evaluating the realtime exhcange rate 
                    df.loc[df["Character ID"]==int(a2),["Price of the Most Expensive Comic"]]=round(float(a4*exc),2)
                    df.to_csv("data.csv",index=False)
                    entry=df[df["Character ID"]==int(a2)].to_dict(orient='records')
                    return {'status': 200, 'response': entry}, 200
                
                else:
                    return {'status': 405, 'response': "Currency not acceptable!"}, 405
                
            else:
                return {'status': 404, 'response': "Character not found!"}, 404
            
        else: 
            return {'status': 402, 'response': "Too many parameters!"}, 402
    ##END OF PUT##
    
       
## END OF CHARACTERS RESOURCE ##
            

##ROUTING RESOURCES TO VARIOUS ENDPOINTS##   
api.add_resource(Characters, '/characters', endpoint='characters')     
api.add_resource(SignUp, '/signup', endpoint='signup')
api.add_resource(LogIn, '/login', endpoint='login')


if __name__ == '__main__':
    app.run(debug=True)