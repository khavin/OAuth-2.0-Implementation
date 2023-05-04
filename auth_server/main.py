from fastapi import Request, Response, status, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
import hashlib
import uuid
import time
import jwt

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongoDBClient = MongoClient('127.0.0.1', 27017)
resourceServerDB = mongoDBClient.resourceServerDB
authSecret = ""

with open("./auth_secret.txt") as f:
    lines = f.readlines()
    authSecret = lines[0]


def getHashedPass(password, salt):

    return hashlib.sha256(
        (password+salt).encode('utf-8')).hexdigest()


def verifyUser(email, password, userKey, passKey):

    if userKey == "clientID":
        cursor = resourceServerDB.clients.find({userKey: email})
    else:
        cursor = resourceServerDB.profiles.find({userKey: email})

    for document in cursor:
        hashedPassword = document[passKey]
        salt = document["salt"]

        hPassFromClient = getHashedPass(password, salt)

        if hPassFromClient.lower() == hashedPassword.lower():
            return True
        else:
            return False

    return False


def verifyAuthCode(clientID, authCode):

    cursor = resourceServerDB.authCodes.find({"authCode": authCode})

    for document in cursor:
        if document["clientID"] == clientID and document["redeemed"] == False and (int(time.time()) - int(document["timestamp"])) <= 3600:
            return (True, {
                "scope": document["scope"],
                "email": document["email"]
            })
        else:
            break

    return (False, None)


@app.post("/auth")
async def auth(request: Request, response: Response):
    requestBody = await request.json()
    email = requestBody.get("email")
    password = requestBody.get("password")
    client_id = requestBody.get("client_id")
    scope = requestBody.get("scope")

    if not verifyUser(email, password, "email", "password"):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "user not authenticated"}

    encoded_jwt = jwt.encode(
        {"email": email, "client_id": client_id, "scope": scope, "timestamp": int(time.time())}, authSecret, algorithm="HS256")

    return encoded_jwt


@app.get("/consent")
async def auth(request: Request, response: Response):

    authorization = request.headers.get('authorization')
    if authorization == None:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "authorization header missing"}

    if "Bearer" not in authorization:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "invalid authorization header"}

    jwt_token = authorization.split("Bearer ")[1]

    try:
        jwt_content = jwt.decode(jwt_token, authSecret, algorithms=["HS256"])
    except Exception as e:
        print("Exception occured while decoding jwt: "+str(e))
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "invalid jwt"}

    email = jwt_content.get("email")
    client_id = jwt_content.get("client_id")
    scope = jwt_content.get("scope")
    timestamp = jwt_content.get("timestamp")

    if int(time.time())-timestamp > 180:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "jwt expired"}

    # generate auth code
    authCode = uuid.uuid4().hex

    # insert auth code to auth code collection
    resourceServerDB.authCodes.insert_one(
        {"email": email, "authCode": authCode, "scope": scope, "redeemed": False, "clientID": client_id, "timestamp": str(time.time()).split(".")[0]})

    return {"message": "User authenticated. Auth code generated", "authCode": authCode}


@app.post("/createUser")
async def auth(request: Request):
    requestBody = await request.json()
    email = requestBody.get("email")
    password = requestBody.get("password")
    favCar = requestBody.get("favCar")
    favCity = requestBody.get("favCity")
    favHero = requestBody.get("favHero")

    # generate salt
    salt = uuid.uuid4().hex
    hashedPass = getHashedPass(password, salt)

    resourceServerDB.profiles.insert_one(
        {"email": email, "password": hashedPass, "salt": salt, "favCar": favCar,
         "favCity": favCity, "favHero": favHero})

    return {"message": "User created!!"}


@app.post("/getToken")
async def auth(request: Request, response: Response):
    requestBody = await request.json()
    code = requestBody.get("code")
    client_id = requestBody.get("client_id")
    client_secret = requestBody.get("client_secret")
    grant_type = requestBody.get("grant_type")

    # verify client id, client secret
    if not verifyUser(client_id, client_secret, "clientID", "clientSecret"):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "client creds are wrong."}

    if grant_type != "authorization_code":
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "grant type not supported."}

    # verity auth code
    authCodeVerification = verifyAuthCode(client_id, code)
    if not authCodeVerification[0]:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "invalid auth code."}

    # update redeemed value
    resourceServerDB.authCodes.update_one(
        {"authCode": code}, {"$set": {"redeemed": True}})

    # generate access token
    accessToken = uuid.uuid4().hex

    # generate salt
    salt = uuid.uuid4().hex
    hashedToken = getHashedPass(accessToken, salt)

    # insert auth code to auth code collection
    resourceServerDB.accessTokens.insert_one(
        {"clientID": client_id, "accessToken": hashedToken, "salt": salt, "scope": authCodeVerification[1]["scope"],
         "email": authCodeVerification[1]["email"], "timestamp": str(time.time()).split(".")[0]})

    return {"access_token": accessToken, "expires_in": 3600, "token_type": "Bearer"}
