import socket
import json
from threading import Thread


class PeerServer:
    def __init__(self, ip, port, files):
        """
        Initialize the server with IP, port, and available pieces for each file.

        Parameters:
        - ip: Server IP address
        - port: Server port
        - files: Dictionary where keys are file names and values are lists of piece IDs available for each file
        """
        self.ip = ip
        self.port = port
        self.files = {file_name: set(pieces) for file_name, pieces in files.items()}

    # Handle individual client connection for piece requests
    def handle_client(self, conn, addr):
        print(f"Connected to peer {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break

            try:
                # Decode data to retrieve request type
                request_parts = data.decode().split(":")

                if not request_parts:
                    conn.sendall(b"Invalid request format")
                    continue

                if request_parts[0] == "REQUEST_PIECE":
                    if len(request_parts) != 3:
                        conn.sendall(b"Invalid REQUEST_PIECE format")
                        continue
                    file_name = request_parts[1]
                    piece_id = int(request_parts[2])

                    # Check if the file and piece are available
                    if file_name in self.files and piece_id in self.files[file_name]:
                        # Here you would read the actual piece data from the file
                        # For demonstration, we'll send placeholder data
                        response = f"data for {file_name} piece {piece_id}".encode()
                        conn.sendall(response)  # Send requested piece data
                        print(f"Sent {file_name} piece {piece_id} to {addr}")
                    else:
                        conn.sendall(b"Piece not available")  # If piece is not available
                else:
                    conn.sendall(b"Unknown request type")
            except (ValueError, IndexError):
                conn.sendall(b"Invalid request format")

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


if __name__ == "__main__":
    # Load peer configurations from JSON
    with open("peers_config.json", "r") as f:
        config = json.load(f)

    for peer in config["peers"]:
        ip = peer["ip"]
        port = peer["port"]
        files = peer["files"]

        # Start each peer server in a separate thread
        server = PeerServer(ip, port, files)
        server_thread = Thread(target=server.start_server)
        server_thread.daemon = True  # Allows program to exit even if thread is running
        server_thread.start()

    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Shutting down peer servers.")