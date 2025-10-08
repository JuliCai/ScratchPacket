class Packet:
    def __init__(self, sender, projectname , id, timestamp, lastping, parentid, payload, type):
        self.sender = sender
        self.projectname = projectname
        self.id = id
        self.timestamp = timestamp
        self.lastping = lastping
        self.parentid = parentid
        self.payload = payload
        self.type = type
        self.responded = False
        self.state = "new"  # new, pingingresponse, responded

class Response:
    def __init__(self, responseid, requestid, timestamp, payload):
        self.responseid = responseid
        self.requestid = requestid
        self.timestamp = timestamp
        self.payload = payload