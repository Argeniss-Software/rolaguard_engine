from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os
import logging
import time

DB_HOST = os.environ["DB_HOST"] 
DB_NAME = os.environ["DB_NAME"] 
DB_USERNAME = os.environ["DB_USERNAME"] 
DB_PASSWORD = os.environ["DB_PASSWORD"] 
DB_PORT = os.environ["DB_PORT"] 

engine = create_engine(f'postgresql+psycopg2://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}', echo='SA_ECHO' in os.environ)

Base = declarative_base()
sessionBuilder = sessionmaker(autoflush=False)
sessionBuilder.configure(bind=engine)
session = sessionBuilder()

while True:
    try:
        engine.connect()
        break
    except Exception as exc:
        logging.warning("Couldn't connect with postgres. Retrying connection.")
        time.sleep(1)

from db.Models import AlertType, RowProcessed, rollback, commit

try:
    if RowProcessed.count() == 0:
        RowProcessed(last_row= 0, analyzer= 'bruteforcer').save_and_flush()
        RowProcessed(last_row= 0, analyzer= 'packet_analyzer').save_and_flush()
        RowProcessed(last_row= 0, analyzer= 'printer').save_and_flush()
        RowProcessed(last_row= 0, analyzer= 'ia_analyzer').save_and_flush() 
        commit()

except Exception as exc:
    logging.error(f'Error at commit when initializing: {exc}')
    rollback()