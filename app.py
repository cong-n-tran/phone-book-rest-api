'''References
1) https://fastapi.tiangolo.com/
2) https://github.com/sumanentc/python-sample-FastAPI-application
3) https://dassum.medium.com/building-rest-apis-using-fastapi-sqlalchemy-uvicorn-8a163ccf3aa1
'''

# Khanh Nguyen Cong Tran
# 10002046419

from fastapi import FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, validator
from sqlalchemy import create_engine, text, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import re
from datetime import datetime


# regex for names
NAME_REGEX = re.compile(
    r"^(?=.{1,50}$)"                              # max length: 50 characters
    r"(?!.*\d)"                                    # No digits
    r"(?!.*['’]{2,})"                              # No double apostrophes
    r"(?!.*--)"                                    # No double hyphens
    r"(?!.*<.*?>)"                                 # No HTML/script-like tags
    r"(?!.*\bselect\b.*\bfrom\b)"                  # No SQL-like patterns
    r"(?!.*;)"                                     # No semicolons
    r"(?!.*\bscript\b)"                            # No 'script' word

    r"(?:"                                         # Group for entire valid pattern

        # Format: First Last [Middle] [Hyphenated] (up to 3 parts max)
        r"[A-Z][a-zA-Z’']{1,39}"                   # First name
        r"(?:[- ][A-Z][a-zA-Z’']{1,39}){0,2}"      # Optional 1–2 more names

        r"|"

        # Format: Last, First [MiddleInitial/Name.]
        r"[A-Z][a-zA-Z’']{1,39}, ?"                # Last name with optional space
        r"[A-Z][a-zA-Z’']{1,39}"                   # First name
        r"(?: (?:[A-Z]\.?|[A-Z][a-zA-Z’']{1,39}))?"# Optional middle initial or full name

        r"|"

        # Single-word name (e.g., Cher)
        r"[A-Z][a-zA-Z’']{1,39}"

    r")$"
)

# regex for the phone number
PHONE_REGEX = re.compile(r'''
^
(                       # Begin entire number group
    (?:\+{1,2}|00|011)?             # Optional international prefix (+, ++, 00, 011)
    [\s\-\.]*

    (?:[1-9]\d{0,2})?               # Optional country code (1–3 digits, not starting with 0)
    [\s\-\.]*

    (?:                            # Area code
        \([1-9]\d{1,3}\)           # e.g. (703) — no leading 0
        |[1-9]\d{1,3}              # or just 703 — no leading 0
    )?                              # Area code is optional

    (?:[\s\-\.])?                   # Optional separator, but now required if area code is present

    (?:\d{3}[\s\-\.]\d{4})          # Require separator in 3-4 format
    |
    (?:\d{5})                       # Or 5-digit extension
    |
    (?:\d{5}[\s\.]\d{5})            # Or 5.5 format like 12345.12345
    |
    (?:\d{2}[\s\.]\d{2}[\s\.]\d{2}[\s\.]\d{2})  # Danish AA AA AA AA
    |
    (?:\d{4}[\s\.]\d{4})            # Danish AAAA AAAA
)
$
''', re.VERBOSE)





# start up the app
app = FastAPI()

#create the database
engine = create_engine("sqlite:///phonebook.db")
Base = declarative_base()

# bind the database to a session
Session = sessionmaker(bind=engine)

# define the header for API key authentication
api_key_header = APIKeyHeader(name="X-API-Key")

# database models
class PhoneBook(Base):
    __tablename__ = "phonebook"
    id = Column(Integer, primary_key=True)
    full_name = Column(String(100))
    phone_number = Column(String(25))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    timestamp = Column(String(30))
    action = Column(String(50))
    details = Column(String(100))

Base.metadata.create_all(engine)

# set up the access depending on the api key
API_KEYS = {
    "read-key": {"role": "read"},
    "admin-key": {"role": "read-write"}
}

# getting the api key every time we do a request
async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key in API_KEYS:
        return API_KEYS[api_key]
    raise HTTPException(status_code=403, detail="Invalid API Key")

# person model 
class Person(BaseModel):
    full_name: str
    phone_number: str
    
    # validating the name with the given regex
    @validator('full_name')
    def validate_name(cls, v):
        if not re.match(NAME_REGEX, v):
            raise ValueError("Invalid name format")
        return v

    #validating the phone numebr with the given regex
    @validator('phone_number')
    def validate_phone(cls, v):
        if not re.match(PHONE_REGEX, v):
            raise ValueError("Invalid phone format")
        return v

# Home page
@app.get("/")
def read_root():
    return {"message": "Welcome to the PhoneBook API! Use /docs to explore the API."}

# audit logging middleware
@app.middleware("http")
async def audit_middleware(request, call_next):
    start_time = datetime.now()
    response = await call_next(request)
    
    session = Session()
    log = AuditLog(
        timestamp=start_time.isoformat(),
        action=f"{request.method} {request.url.path}",
        details=f"Status {response.status_code}"
    )
    session.add(log)
    session.commit()
    session.close()
    
    return response

# API Endpoints with parameterized queries
@app.get("/PhoneBook/list", dependencies=[Security(get_api_key)])
def list_entries():
    session = Session()
    try:
        # Parameterized SELECT using raw SQL
        result = session.execute(text("SELECT * FROM phonebook"))
        entries = [dict(row) for row in result.mappings()]
        return entries
    finally:
        session.close()

# adding a user
@app.post("/PhoneBook/add")
def add_entry(
    person: Person,
    credentials: dict = Security(get_api_key, scopes=["read-write"])
):
    # create the session
    session = Session()

    # normalize the phone numbers 
    normalized_phone_number = re.sub(r'\D', '', person.phone_number)  # Remove non-digit characters
    person.phone_number = normalized_phone_number
    # - the encoded phone numbers were improperly being stored in the database 
    #   so we need to normalize all phone numbers. 
    # - this also helps with keep primary keys (the phone number) consistent and prevents duplicates
    #   numbers from being added 

    try:
        # creating the SQL query for existing entries
        check_stmt = text("""
            SELECT * FROM phonebook 
            WHERE phone_number = :phone_number
        """)
        existing = session.execute(
            check_stmt,
            {"phone_number": person.phone_number}
        ).fetchone()
        
        # throw error if query actually return something
        if existing:
            raise HTTPException(400, "Person already exists in the database")

        # create sql query to add an entry
        insert_stmt = text("""
            INSERT INTO phonebook (full_name, phone_number)
            VALUES (:full_name, :phone_number)
        """)
        session.execute(
            insert_stmt,
            person.dict()
        )
        session.commit()

        # return successful request
        return {"message": "Person added successfully"}
    finally:
        session.close()

# delete an entry by name
@app.put("/PhoneBook/deleteByName")
def delete_by_name(
    full_name: str,
    credentials: dict = Security(get_api_key, scopes=["read-write"])
):
    #create session
    session = Session()
    try:
        # create sql query to delete user by name (also deletes every instances of that user as well - dup names but different numbers)
        delete_stmt = text("""
            DELETE FROM phonebook 
            WHERE full_name = :full_name
        """)
        result = session.execute(delete_stmt, {"full_name": full_name})
        session.commit()
        
        # if our sql query returns nothing, throw error bc we didn't find an entry with that name
        if result.rowcount == 0:
            raise HTTPException(404, "Person not found in the database with that name")
            
        # return sucessful delete request by name otherweise
        return {"message": "Person deleted successfully by name"}
    finally:
        session.close()

@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(
    phone_number: str,
    credentials: dict = Security(get_api_key, scopes=["read-write"])
):
    #create session
    session = Session()

    # normalize the number like normal
    normalized_number = re.sub(r'\D', '', phone_number)
    phone_number = normalized_number
    try:
        # create the sql query to delete by number
        delete_stmt = text("""
            DELETE FROM phonebook 
            WHERE phone_number = :phone_number
        """)
        result = session.execute(delete_stmt, {"phone_number": phone_number})
        session.commit()
        
        # if the sql query returns nothing then we throw error that we didn't find that entry with the phone number
        if result.rowcount == 0:
            raise HTTPException(404, "Person not found in the database with that phone number")
            
        # return a successful delete by number request
        return {"message": "Person deleted successfully by phone number"}
    finally:
        session.close()

