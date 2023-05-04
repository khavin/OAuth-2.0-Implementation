from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()
origins = ["*"]
app.mount("/site", StaticFiles(directory="./static", html=True), name="site")
