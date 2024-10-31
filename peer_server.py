import socket
import argparse
from threading import Thread

class PeerServer:
    def __init__(self, ip, port, pieces):
        self.ip = ip
        self.port = port
        self.pieces = pieces

    # Handle individual client connection for piece requests
    def handle_client(self, conn, addr):
        print(f"Connected to peer {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            piece_id = int(data.decode())  # Decode requested piece ID
            if piece_id in self.pieces:
                response = f"data for piece {piece_id}"
                conn.sendall(response.encode())  # Send requested piece data
                print(f"Sent piece {piece_id} to {addr}")
            else:
                conn.sendall(b"Piece not available")  # If piece is not available
        conn.close()

    # Start the peer server to listen for incoming requests
    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.ip, self.port))
            server_socket.listen(5)
            print(f"Peer server {self.ip}:{self.port} is listening...")
            while True:
                conn, addr = server_socket.accept()
                client_thread = Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start a peer server.")
    parser.add_argument("--ip", type=str, required=True, help="IP address of the peer server")
    parser.add_argument("--port", type=int, required=True, help="Port for the peer server")
    parser.add_argument("--pieces", type=int, nargs='+', required=True, help="List of piece IDs this peer has")

    args = parser.parse_args()

    # Start the peer server with provided IP, port, and pieces
    peer_server = PeerServer(args.ip, args.port, args.pieces)
    peer_server.start_server()
