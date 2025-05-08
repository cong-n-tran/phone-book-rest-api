'''References
1) https://fastapi.tiangolo.com/
2) https://github.com/sumanentc/python-sample-FastAPI-application
3) https://dassum.medium.com/building-rest-apis-using-fastapi-sqlalchemy-uvicorn-8a163ccf3aa1
'''
# Import the required modules
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Create the FastAPI app
app = FastAPI()

# Create the SQLite database engine
engine = create_engine("sqlite:///phonebook.db", echo=True)

# Create the base class for the database models
Base = declarative_base()

# Create the PhoneBook model class
class PhoneBook(Base):
    __tablename__ = "phonebook"

    id = Column(Integer, primary_key=True)
    full_name = Column(String)
    phone_number = Column(String)

    '''def __repr__(self):
        return f"<PhoneBook(full_name={self.full_name}, last_name={self.last_name}, phone_number={self.phone_number})>" '''

# Create the database schema
Base.metadata.create_all(engine)

# Create the session class for database operations
Session = sessionmaker(bind=engine)

# Create the Pydantic model class for request and response data
class Person(BaseModel):
    full_name: str
    phone_number: str

# Define the API endpoints

@app.get("/PhoneBook/list")
def list_phonebook():
    # Get a new session
    session = Session()
    # Query all the records in the phonebook table
    phonebook = session.query(PhoneBook).all()
    # Close the session
    session.close()
    # Return the list of records as JSON objects
    return phonebook

@app.post("/PhoneBook/add")
def add_person(person: Person):
    # Get a new session
    session = Session()
    # Check if the person already exists in the database by phone number
    existing_person = session.query(PhoneBook).filter_by(phone_number=person.phone_number).first()
    # If the person exists, raise an exception
    if existing_person:
        session.close()
        raise HTTPException(status_code=400, detail="Person already exists in the database")
    # Otherwise, create a new PhoneBook record and add it to the database
    new_person = PhoneBook(full_name=person.full_name, phone_number=person.phone_number)
    session.add(new_person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person added successfully"}

@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str):
    # Get a new session
    session = Session()
    # Query the person by name in the database
    person = session.query(PhoneBook).filter_by(full_name=full_name).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person deleted successfully"}

@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str):
    # Get a new session
    session = Session()
    # Query the person by phone number in the database
    person = session.query(PhoneBook).filter_by(phone_number=phone_number).first()
    # If the person does not exist, raise an exception
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    # Otherwise, delete the person from the database
    session.delete(person)
    session.commit()
    # Close the session
    session.close()
    # Return a success message
    return {"message": "Person deleted successfully"}