import socket
import os

class FileDownloader:
    def __init__(self, file_name, peers, download_path):
        self.file_name = file_name
        self.peers = peers
        self.download_path = download_path

    def download_from_peer(self, peer):
        peer_host, peer_port = peer.split(":")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_host, int(peer_port)))
        client_socket.send(self.file_name.encode())

        file_path = os.path.join(self.download_path, self.file_name)
        with open(file_path, 'wb') as f:
            data = client_socket.recv(512 * 1024)
            while data:
                f.write(data)
                data = client_socket.recv(512 * 1024)

        client_socket.close()

    def start(self):
        for peer in self.peers:
            print(f"Trying to download {self.file_name} from {peer}")
            self.download_from_peer(peer)
