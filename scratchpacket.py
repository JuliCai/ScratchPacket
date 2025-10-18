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
    
    def __str__(self):
        return f"Packet(sender={self.sender}, projectname={self.projectname}, id={self.id}, timestamp={self.timestamp}, lastping={self.lastping}, parentid={self.parentid}, payload={self.payload}, type={self.type}, responded={self.responded}, state={self.state})"

class Response:
    def __init__(self, responseid, requestid, timestamp, payload):
        self.responseid = responseid
        self.requestid = requestid
        self.timestamp = timestamp
        self.payload = payload

    def __str__(self):
        return f"Response(responseid={self.responseid}, requestid={self.requestid}, timestamp={self.timestamp}, payload={self.payload})"

class Save:
    def __init__(self, username, data, lastsaved, firstsaved):
        self.username = username
        self.data = data
        self.lastsaved = lastsaved
        self.firstsaved = firstsaved

    def __str__(self):
        return f"Save(username={self.username}, data={self.data}, lastsaved={self.lastsaved}, firstsaved={self.firstsaved})"