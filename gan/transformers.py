# transformers.py
import javaobj.v2 as javaobj
from javaobj.v2.api import ObjectTransformer
from gan.instances import ServerMessageHeaderInstance, ServerRouteDetailsInstance, ServerIdInstance

class HeaderTransformer(ObjectTransformer):
    def create_instance(self, classdesc):
        if classdesc.name.endswith("ServerMessage$ServerMessageHeader") or classdesc.name.endswith("ServerMessageHeader"):
            return ServerMessageHeaderInstance()
        return None

class ServerIdTransformer(ObjectTransformer):
    def create_instance(self, classdesc):
        if classdesc.name.endswith("ServerId"):
            return ServerIdInstance()
        return None

class ServerRouteDetailsTransformer(ObjectTransformer):
    def create_instance(self, classdesc):
        if classdesc.name.endswith("metro.impl.ServerRouteDetails"):
            return ServerRouteDetailsInstance()
        return None
