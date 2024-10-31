import socket
import json
import threading
from time import sleep
from collections import defaultdict


class PeerClient:
    def __init__(self, ip, port, available_pieces):
        """
        Initialize the PeerClient with IP, port, and available pieces.

        Parameters:
        - ip: Peer server IP address
        - port: Peer server port
        - available_pieces: Dictionary where keys are file names and values are sets of piece IDs available
        """
        self.ip = ip
        self.port = port
        self.available_pieces = {file_name: set(pieces) for file_name, pieces in available_pieces.items()}
        self.client_socket = None
        self.lock = threading.Lock()  # To ensure thread-safe operations on the socket

    def connect(self):
        """Establish a persistent connection to the peer server."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.ip, self.port))
            print(f"Connected to peer {self.ip}:{self.port}")
        except ConnectionError:
            print(f"Could not connect to peer {self.ip}:{self.port}")

    def request_piece(self, file_name, piece_id):
        """Request a specific piece of a file over a persistent connection."""
        if not self.client_socket:
            self.connect()
            if not self.client_socket:
                return None  # Return if connection fails

        try:
            request = f"REQUEST_PIECE:{file_name}:{piece_id}"
            with self.lock:  # Ensure only one thread accesses the socket at a time
                self.client_socket.sendall(request.encode())  # Send piece request
                data = self.client_socket.recv(4096)
            if data in [b"Piece not available", b"Unknown request type", b"Invalid request format"]:
                return None
            return data  # Return raw data
        except (ConnectionError, BrokenPipeError):
            print(f"Connection lost with peer {self.ip}:{self.port}")
            self.client_socket.close()
            self.client_socket = None
            return None

    def close_connection(self):
        """Close the persistent connection."""
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None


class TorrentDownloader:
    def __init__(self, peer_configs, files):
        """
        Initialize with a list of peer configurations and a dictionary of files with their needed pieces.

        Parameters:
        - peer_configs: List of dictionaries containing peer information
        - files: Dictionary where keys are file names and values are sets of pieces needed
        """
        self.peer_configs = peer_configs  # List of peer configurations
        self.files = {file_name: set(pieces) for file_name, pieces in files.items()}
        self.downloaded_pieces = {file_name: set() for file_name in files}
        self.lock = threading.Lock()

    def download_file(self, file_name, pieces_needed):
        """Download all pieces of a single file."""
        # Create separate PeerClient instances for this thread
        peers = []
        for peer_config in self.peer_configs:
            ip = peer_config["ip"]
            port = peer_config["port"]
            files = peer_config["files"]
            peers.append(PeerClient(ip, port, files))

        # Establish connections to each peer server
        for peer in peers:
            peer.connect()

        while pieces_needed:
            rarest_pieces = self.get_rarest_pieces(file_name, pieces_needed, peers)
            if not rarest_pieces:
                print(f"No available peers have the remaining pieces for '{file_name}'.")
                break
            print(f"File: {file_name} - Rarest pieces needed: {rarest_pieces}")

            for piece in rarest_pieces:
                if piece not in pieces_needed:
                    continue

                available_peers = [
                    peer for peer in peers
                    if file_name in peer.available_pieces and piece in peer.available_pieces[file_name]
                ]

                if not available_peers:
                    print(f"No peers have piece {piece} for file '{file_name}'.")
                    continue

                for peer in available_peers:
                    data = peer.request_piece(file_name, piece)
                    if data is None:
                        print(f"Failed to download piece {piece} from {peer.ip}:{peer.port} for file '{file_name}'")
                        continue

                    # Save the downloaded piece
                    self.save_piece(data, file_name, piece)

                    # Update downloaded and remaining pieces for the file
                    with self.lock:
                        self.downloaded_pieces[file_name].add(piece)
                        pieces_needed.discard(piece)

                    print(f"Downloaded piece {piece} from {peer.ip}:{peer.port} for file '{file_name}'")
                    break  # Move to the next piece after successful download

            sleep(1)

        if not pieces_needed:
            print(f"All pieces for file '{file_name}' downloaded.")
            self.assemble_file(file_name, len(self.files[file_name]))
        else:
            print(f"Download incomplete for file '{file_name}'.")

        # Close each peer connection after download is complete
        for peer in peers:
            peer.close_connection()

    def get_rarest_pieces(self, file_name, pieces_needed, peers):
        """Determine the rarest pieces from the peers for a specific file."""
        piece_counts = defaultdict(int)
        for peer in peers:
            if file_name in peer.available_pieces:
                for piece in peer.available_pieces[file_name]:
                    if piece in pieces_needed:
                        piece_counts[piece] += 1
        if not piece_counts:
            return []
        # Sort pieces by rarity (ascending order)
        return sorted(pieces_needed, key=lambda x: piece_counts.get(x, 0))

    def save_piece(self, data, file_name, piece):
        """Save a downloaded piece for a specific file."""
        if data:
            print(f"Saving piece {piece} of file '{file_name}'")
            with open(f"{file_name}.part{piece}", "wb") as f:
                f.write(data)  # Write raw binary data

    def assemble_file(self, file_name, total_pieces):
        """Assemble all downloaded pieces into the final file."""
        with open(file_name, "wb") as final_file:
            for piece_id in sorted(self.downloaded_pieces[file_name]):
                with open(f"{file_name}.part{piece_id}", "rb") as piece_file:
                    final_file.write(piece_file.read())
                # Optionally, remove the piece file after assembling
                # os.remove(f"{file_name}.part{piece_id}")
        print(f"File '{file_name}' has been assembled successfully.")

    def start_downloading(self):
        """Start downloading each file in a separate thread."""
        threads = []
        for file_name, pieces_needed in self.files.items():
            thread = threading.Thread(target=self.download_file, args=(file_name, pieces_needed.copy()))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print("All files downloaded.")


# Usage
if __name__ == "__main__":
    # Load peer configurations from JSON
    with open("peers_config.json", "r") as f:
        config = json.load(f)

    peer_configs = config["peers"]

    # Define files to download and their required pieces
    files = {
        "file1": {1, 2, 3, 4, 5},
        "file2": {1, 2, 3, 4, 5}
    }

    downloader = TorrentDownloader(peer_configs, files)
    downloader.start_downloading()