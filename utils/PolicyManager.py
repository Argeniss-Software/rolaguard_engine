import os
import pika
import json
import time
import logging as log
from threading import Thread
from db.Models import Policy



class PolicyManager():
    def __init__(self):
        self.reload_policies()
        self.needs_reloading = False


    def use_policy(self, data_collector_id):
        try:
            if self.needs_reloading:
                self.reload_policies()
            if self.active_dc_id != data_collector_id:
                self.active_policy = self.policy[self.policy_by_dc[data_collector_id]]
                self.active_dc_id = data_collector_id
        except Exception as exc:
            log.error(f"Error trying to change the active policy: {exc}")


    def is_enabled(self, alert_type):
        try:
            for item in self.active_policy.items:
                if item.alert_type_code == alert_type:
                    return item.enabled
            return True
        except Exception as exc:
            log.error(f"Error on is_enabled for alert {alert_type}. Exception: {exc}")
            return False


    def get_parameters(self, alert_type):
        try:
            for item in self.active_policy.items:
                if item.alert_type_code == alert_type:                    
                    default_parameters = json.loads(item.alert_type.parameters)
                    default_parameters = {par : val['default'] for par, val in default_parameters.items()}
                    parameters = json.loads(item.parameters)
                    parameters = {par : val for par, val in parameters.items()}

                    # Add missing default parameters and update the item if needed
                    needs_update = False
                    for par, val in default_parameters.items():
                        if par not in parameters:
                            needs_update = True
                            parameters[par] = val
                    if needs_update:
                        item.parameters = json.dumps(parameters)
                        item.db_update()

                    return parameters

            # If no item found for this alert_type, add it with default parameters and return them
            return self.active_policy.add_missing_item(alert_type)

        except Exception as exc:
            log.error(f"Error getting parameters of alert {alert_type}. Exception: {exc}")
        return {}


    def subscribe_to_events(self):
        try:
            def connect_to_mq():
                time.sleep(2)
                rabbit_credentials = pika.PlainCredentials(username = os.environ["RABBITMQ_DEFAULT_USER"],
                                                           password = os.environ["RABBITMQ_DEFAULT_PASS"])
                rabbit_parameters = pika.ConnectionParameters(host = os.environ["RABBITMQ_HOST"],
                                                              port = os.environ["RABBITMQ_PORT"],
                                                              credentials = rabbit_credentials)
                connection = pika.BlockingConnection(rabbit_parameters)
                channel = connection.channel()
                channel.exchange_declare(exchange='policies_events', exchange_type='fanout')
                result = channel.queue_declare(queue='', exclusive=True)
                queue_name = result.method.queue
                channel.queue_bind(exchange='policies_events', queue=queue_name)
                channel.basic_consume(on_message_callback=self._handle_events, queue=queue_name, auto_ack=True)
                channel.start_consuming()

            thread = Thread(target = connect_to_mq)
            thread.setDaemon(True)
            thread.start()
        except Exception as exc:
            log.error(f"Error: could not subscribe to policy events. Exception: {exc}")


    def _handle_events(self, ch, method, properties, body):
        try:
            self.needs_reloading = True
        except Exception as exc:
            log.error(f"Could not handle policy event. Exception: {exc}")
            return

    def reload_policies(self):
        self.policy = {p.id : p for p in Policy.find()}
        self.policy_by_dc = {dc.id : p.id for p in self.policy.values() for dc in p.data_collectors}
        self.active_dc_id = None
        self.active_policy = None