from fastapi import Request, Response, status, FastAPI, HTTPException
from pymongo import MongoClient
import hashlib
import time

app = FastAPI()
mongoDBClient = MongoClient('127.0.0.1', 27017)
resourceServerDB = mongoDBClient.resourceServerDB


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


def fetchUserData(email, scope):

    cursor = resourceServerDB.profiles.find({"email": email})

    for document in cursor:
        data = {}
        for entry in scope.split(","):
            data[entry] = document[entry]

        return data

    return {}


def verifyAccessToken(clientID, accessToken):

    cursor = resourceServerDB.accessTokens.find({"clientID": clientID})

    for document in cursor:
        if document["clientID"] == clientID:
            if document["accessToken"] == getHashedPass(accessToken, document["salt"]) and (int(time.time()) - int(document["timestamp"])) <= 3600:
                return (True, {
                    "scope": document["scope"],
                    "email": document["email"]
                })
        else:
            break

    return (False, None)


@app.post("/getData")
async def auth(request: Request, response: Response):
    print("getData api called")
    requestBody = await request.json()
    client_id = requestBody.get("client_id")
    client_secret = requestBody.get("client_secret")
    accessToken = requestBody.get("access_token")

    # verify client id, client secret
    if not verifyUser(client_id, client_secret, "clientID", "clientSecret"):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "client creds are wrong."}

    # verity auth code
    authCodeVerification = verifyAccessToken(client_id, accessToken)
    if not authCodeVerification[0]:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "invalid access token."}

    userData = fetchUserData(
        authCodeVerification[1]["email"], authCodeVerification[1]["scope"])

    return userData
