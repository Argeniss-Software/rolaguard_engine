import random
import logging as log
from db import session


class ObjectTableCache():
    """
    Class to generate an in-memory cache of a DB table. The SQLAlchemy model of the table
    has to define the method find_with and get.
    """
    def __init__(self, table, max_cached_items = float('Inf')):
        self.table = table
        self.cached_items = {}
        self.max_cached_items = max_cached_items

    def find_with(self, **kargs):
        query_key = tuple(kargs.values())
        try:
            return self.cached_items[query_key]
        except:
            item = self.table.find_with(**kargs)
            if item: self.add_to_cache(query_key, item)
            return item

    def get(self, id):
        return self.table.get(id) 

    def insert(self, item):
        try:
            session.add(item)
            session.commit()
        except Exception as exc:
            session.rollback()
            log.error(f"Error inserting object in db (rolled back): {exc}")

    def create_from_packet(self, packet):
        return self.table.create_from_packet(packet)

    def add_to_cache(self, query_key, item):
        # TODO: improve the garbage collection to reduce cache misses
        if len(self.cached_items) > self.max_cached_items:
            random_key = random.choice(self.cached_items.keys())
            del self.cached_items[random_key]
        self.cached_items[query_key] = item


class AssociationTableCache():
    """
    Class to generate an in-memory cache of a DB table. The SQLAlchemy model of the table
    has to define the methods associated_with and associate.
    """
    def __init__(self, table, max_cached_items = float('Inf')):
        self.table = table
        self.cached_items = {}
        self.max_cached_items = max_cached_items

    def associated_with(self, item):
        items = self.table.associated_with(item)
        if items: self.add_to_cache(item, items)
        return items

    def associate(self, item_1, item_2):
        if item_1 in self.cached_items and item_2 in self.cached_items[item_1]:
            return
        else:
            self.table.associate(item_1, item_2)
            self.add_to_cache(item_1, [item_2])

    def add_to_cache(self, item_1, items):
        # TODO: improve the garbage collection to reduce cache misses
        if len(self.cached_items) > self.max_cached_items:
            random_key = random.choice(self.cached_items.keys())
            del self.cached_items[random_key]

        if item_1 in self.cached_items:
            self.cached_items[item_1] = self.cached_items[item_1].union(items)
        else:
            self.cached_items[item_1]= set(items)