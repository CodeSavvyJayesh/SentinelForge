## this is fastapi app
from fastapi import FastAPI

app = FastAPI(
    title="SentinelForge",
    description="AI powered zero-trust devsecops security engine",

)

@app.get("/")
def root():
    return{
        "message": "running"
    }