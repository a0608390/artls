from amsg import *
from socketserver import *
import pysnooper


class Artls(BaseRequestHandler):

    def handle(self):

        try:
            while True:
                pkt = self.request[0]
                server = self.request[1]
                addr = self.client_address
                ap_msg = MSG(pkt)
                ap_msg.view()

                # confirm send ae message
                if ap_msg.message_type == b'\x00\x15':
                    msg_10 = ap_msg.push_10()
                    server.sendto(msg_10, addr)
                    break

                else:
                    break
        except Exception as msg:
            print(msg)


if __name__ == '__main__':
    host = ('192.168.1.14', 8888)

    server = UDPServer(host, Artls)
    server.serve_forever()

