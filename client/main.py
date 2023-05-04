from fastapi import Request, FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import json

clientSecret = ""

with open("./client_secret.txt") as f:
    lines = f.readlines()
    clientSecret = lines[0]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_server = "http://localhost:8000/"
resource_server = "http://localhost:8090/"


@app.post("/exchangeAuthCodeAndGetData")
async def auth(request: Request):
    print("exchanging auth code and getting access token")
    requestBody = await request.json()

    authCode = requestBody.get("authCode")
    clientID = "localhostClient"

    payload = {
        "code": authCode,
        "client_id": "localhostClient",
        "client_secret": clientSecret,
        "grant_type": "authorization_code"
    }

    response = requests.post(auth_server+"getToken", data=json.dumps(payload))

    print("Get Access Token: "+str(response.status_code))

    if response.status_code == 200:
        accessToken = response.json()["access_token"]
    else:
        return {"message": "unable to get access token"}

    payload = {
        "access_token": accessToken,
        "client_id": clientID,
        "client_secret": clientSecret
    }

    print("exchanging access token for user data")
    response = requests.post(resource_server+"getData",
                             data=json.dumps(payload))

    print("Get User Data: "+str(response.status_code))

    return response.json()
