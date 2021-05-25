from bson import ObjectId
from . import manager, users
import socket


def check_status(host, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        print(ex)
        return False


class User():
    def __init__(self, login):
        self.login = login

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.login

    @manager.user_loader
    def load_user(login):
        if login == 'admin':
            return User(login=login)
        else:
            u = users.find_one({"last_name": login})
            if not u:
                return None
            return User(login=u['last_name'])


def insert_document(collection, data):
    return collection.insert_one(data).inserted_id


def find_document(collection, elements=None, multiple=False, single=False):
    if multiple:
        results = collection.find(elements)
        return [r for r in results]
    elif single:
        return collection.find_one(elements)
    else:
        results = collection.find()
        return [r for r in results]


def update_document(collection, query_elements, new_values_one):
    collection.update_one(query_elements, {'$set': new_values_one})


def delete_document(collection, query):
    collection.delete_one(query)


