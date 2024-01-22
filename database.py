import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

if os.environ.get("DEPLOYMENT") == "development":
    engine = create_engine('sqlite:///users.db')
    db_session = scoped_session(sessionmaker(autocommit=False,
                                            autoflush=False,
                                            bind=engine))
    
elif os.environ.get("DEPLOYMENT") == "production":
    engine = create_engine(os.environ.get("PROD_DB_STRING"))
    db_session = scoped_session(sessionmaker(autocommit=False,
                                            autoflush=False,
                                            bind=engine))

else:
    logging.critical("No DEPLOYMENT variable set, quitting.")
    quit

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    import models
    Base.metadata.create_all(bind=engine)