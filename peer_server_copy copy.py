import socket
import argparse
from threading import Thread


class PeerServer:
    def __init__(self, ip, port, files):

        self.ip = ip
        self.port = port

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


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start a peer server.")
    parser.add_argument("--ip", type=str, required=True, help="IP address of the peer server")
    parser.add_argument("--port", type=int, required=True, help="Port for the peer server")
    parser.add_argument("--files", type=str, nargs='+', required=True, 
                        help="Files and pieces this peer has in format: file1:1,2,3 file2:4,5")

    args = parser.parse_args()

    # Parse file pieces into a dictionary
    files = {}
    for file_arg in args.files:
        try:
            file_name, pieces_str = file_arg.split(":")
            pieces = set(map(int, pieces_str.split(",")))
            files[file_name] = pieces
        except ValueError:
            print(f"Invalid file format: {file_arg}. Expected format 'file:1,2,3'")
            exit(1)

    # Start the peer server with provided IP, port, and available files
    peer_server = PeerServer(args.ip, args.port, files)
    peer_server.start_server()