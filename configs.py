
import json

CFG = {
    "directory": {
        "logs_dir": "logs/",
        "node_files_dir": "node_files/",
        "tracker_db_dir": "tracker_DB/",
        "backup_tracker_db_dir": "backup_tracker_DB/",
    },
    "constants": {
        "AVAILABLE_PORTS_RANGE": (1024, 65535), # range of available ports on the local computer
        "PEER_HOST": 'localhost',
        "TRACKER_ADDR": ('localhost', 12345), #cần chỉnh
        "TRACKER_ADDR_PROXY": ('localhost', 12367),#cần chỉnh
        "TRACKER_ADDR_BACKUP": ('localhost', 12389),#cần chỉnh
        "TRACKER_PORT_LISTEN": 23456,
        "tracker_update_port": 12390,
        "BUFFER_SIZE": 8192,  # TCP buffer size (8KB is a typical TCP buffer size)
        "CHUNK_PIECES_SIZE": 2000,  # Adjust chunk size for TCP, leaving some overhead
        "MAX_SPLITTNES_RATE": 3,    # number of neighboring peers which the node take chunks of a file in parallel
        "NODE_TIME_INTERVAL": 20,        # the interval time that each node periodically informs the tracker (in seconds)
        "TRACKER_TIME_INTERVAL": 22      #the interval time that the tracker periodically checks which nodes are in the torrent (in seconds)
    }
}


class Config:

    def __init__(self, directory, constants, ):
        self.directory = directory
        self.constants = constants

    @classmethod
    def from_json(cls, cfg):
        """Creates config from json"""
        params = json.loads(json.dumps(cfg), object_hook=HelperObject)
        return cls(params.directory, params.constants)


class HelperObject(object):
    """Helper class to convert json into Python object"""
    def __init__(self, dict_):
        self.__dict__.update(dict_)