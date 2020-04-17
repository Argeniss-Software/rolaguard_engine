import pika
import json
import os
import logging

from threading import Thread


def emit_alert_event(type, data):

    def emitter():
        try:    
            rabbit_credentials = pika.PlainCredentials(os.environ.get("RABBITMQ_DEFAULT_USER"), os.environ.get("RABBITMQ_DEFAULT_PASS"))
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=os.environ.get("RABBITMQ_HOST"), port=os.environ.get("RABBITMQ_PORT"), credentials=rabbit_credentials))
            channel = connection.channel()
            channel.queue_declare(queue='alert_events')
            data['event_type'] = type
            body = json.dumps(data)
            channel.basic_publish(exchange='', routing_key='alert_events', body=body.encode('utf-8'))
            connection.close()
        except Exception as e:
            logging.error("There was an error with MQ. Exception: {0}".format(e))
    
    thread = Thread(target = emitter)
    thread.setDaemon(True)
    thread.start()
