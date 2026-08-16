# inside this we have to create models.... 
# user, project, repo, scan, vulnerability, risk-assess, patch, report, feeback 
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass