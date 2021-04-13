
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
