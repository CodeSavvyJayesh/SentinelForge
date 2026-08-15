# here we will be writing code related to health of system 
# this will be responsible for health api 
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "healthy"
    }