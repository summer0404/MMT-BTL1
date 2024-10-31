import socket
import threading
from time import sleep
from collections import defaultdict

class PeerClient:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def request_piece(self, piece_id):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.ip, self.port))
                client_socket.sendall(str(piece_id).encode())  # Send piece request
                data = client_socket.recv(1024)
                return data.decode()
        except ConnectionError:
            print(f"Could not connect to peer {self.ip}:{self.port}")
            return None

class TorrentDownloader:
    def __init__(self, peers, pieces_needed):
        self.peers = peers
        self.pieces_needed = set(pieces_needed)
        self.pieces_downloaded = set()
        self.lock = threading.Lock()

    def get_rarest_pieces(self):
        piece_counts = defaultdict(int)
        for peer in self.peers:
            available_pieces = self.check_peer_pieces(peer)
            for piece in available_pieces:
                piece_counts[piece] += 1

        sorted_rarest_pieces = sorted(piece_counts, key=piece_counts.get)
        return [piece for piece in sorted_rarest_pieces if piece in self.pieces_needed]

    def check_peer_pieces(self, peer):
        return self.pieces_needed  # Placeholder; update to get pieces available from peer

    def save_piece(self, data, piece):
        # Placeholder function for saving the downloaded piece
        # Ensure this is thread-safe if accessing shared resources
        if data:
            print(f"Piece {piece} saved.")
            # Implement actual saving logic here

    def download_piece_from_peer(self, peer, piece):
        try:
            data = peer.request_piece(piece)
            if data is None:
                print(f"Failed to download piece {piece} from {peer.ip}:{peer.port}")
                return

            with self.lock:
                if piece in self.pieces_downloaded:
                    print(f"Piece {piece} already downloaded by another thread.")
                    return
                self.pieces_downloaded.add(piece)

            self.save_piece(data, piece)
            
            with self.lock:
                self.pieces_needed.discard(piece)
                
            print(f"Downloaded piece {piece} from {peer.ip}:{peer.port}")

        except TimeoutError:
            print(f"Timeout while downloading piece {piece} from {peer.ip}:{peer.port}")

    def start_downloading(self):
        while self.pieces_needed:
            rarest_pieces = self.get_rarest_pieces()
            print(f"Rarest pieces needed: {rarest_pieces}")

            threads = []
            for piece in rarest_pieces:
                if piece not in self.pieces_needed:
                    continue
                for peer in self.peers:
                    thread = threading.Thread(target=self.download_piece_from_peer, args=(peer, piece))
                    threads.append(thread)
                    thread.start()

            for thread in threads:
                thread.join()
            
            sleep(1)

        print("All pieces downloaded.")

# Usage
if __name__ == "__main__":
    peers = [
        PeerClient("127.0.0.1", 33357),
        PeerClient("127.0.0.1", 33358),
        PeerClient("127.0.0.1", 33359),
    ]

    pieces_needed = [1, 2, 3, 4, 5]
    downloader = TorrentDownloader(peers, pieces_needed)
    downloader.start_downloading()
