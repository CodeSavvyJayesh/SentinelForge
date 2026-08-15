# here we have to make sure we are writing the config code! 

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "SentinelForge API"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True


settings = Settings()
