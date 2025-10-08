import scratchattach as sa
from scratchPacket import Packet
import time

cloud = sa.get_tw_cloud("1225704696")

while True:
    cloud.set_var("CLOUD_CLIENT_DATA_1", "67")