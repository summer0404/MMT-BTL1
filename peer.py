import socket
import threading
import os
import shutil
import time
from file_downloader import FileDownloader
from magnet import MetainfoFile, MagnetText

TRACKER_HOST = '10.0.175.151'
TRACKER_PORT = 65432

class Peer:
    def __init__(self, peer_name, port=0):
        self.peer_name = peer_name
        self.host = self.get_local_ip()
        self.port = port
        self.repo_path = f"peer_files/{peer_name}/"
        self.shared_files = {}  # Lưu các file và các phần đã có để chia sẻ
        self.peer_scores = {}  # Điểm để đánh giá các peer dựa trên tit-for-tat
        self.neighbors = {}  # Ghi lại peer và các file mà neighbor có
        self.file_pieces = {}  # Thông tin về các pieces mà peer hiện có

        if not os.path.exists(self.repo_path):
            os.makedirs(self.repo_path)

    def upload_files(self, file_paths):
        threads = []
        for file_path in file_paths.split():
            if os.path.isfile(file_path):
                thread = threading.Thread(target=self.register_file, args=(file_path,))
                threads.append(thread)
                thread.start()
            else:
                print(f"File not found: {file_path}")
                
        for thread in threads:
            thread.join()

    def get_local_ip(self):
        # Tạo một socket tạm thời để xác định địa chỉ IP nội bộ
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Kết nối tới một địa chỉ ngoài để lấy IP nội bộ
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception as e:
            print("Error retrieving local IP:", e)
            local_ip = '127.0.0.1'  # Nếu thất bại, dùng localhost như là dự phòng
        finally:
            s.close()
        return local_ip

    def register_file(self, file_path):
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.repo_path, file_name)
        shutil.copy(file_path, dest_path)
        print(f"File {file_name} has been copied to {self.repo_path}")

        tracker_address = f"{TRACKER_HOST}:{TRACKER_PORT}"
        metainfo = MetainfoFile(dest_path, tracker_address)
        metainfo.save()
        
        self.shared_files[file_name] = metainfo.pieces
        self.file_pieces[file_name] = set(metainfo.pieces)  # Lưu các pieces hiện có

        magnet_link = MagnetText.generate_magnet_link(dest_path)
        print(f"Magnet link for {file_name}: {magnet_link}")

         # Đăng ký file với tracker
        tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_socket.connect((TRACKER_HOST, TRACKER_PORT))
        register_message = f"REGISTER {self.host}:{self.port} {file_name}"
        tracker_socket.send(register_message.encode())
        tracker_socket.close()
        print(f"Registered {file_name} with tracker at {self.host}:{self.port}")

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        self.port = server_socket.getsockname()[1]
        server_socket.listen(5)
        print(f"Peer {self.peer_name} running on {self.host}:{self.port}")
        
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_client(self, conn):
        request = conn.recv(1024).decode().split()
        if request[0] == "PIECES":
            file_name = request[1]
            if file_name in self.file_pieces:
                conn.send(f"PIECES {file_name} {' '.join(self.file_pieces[file_name])}".encode())
        elif request[0] == "GET":
            file_name = request[1]
            piece_id = request[2]
            file_path = os.path.join(self.repo_path, file_name)
            if os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    f.seek(int(piece_id) * 512 * 1024)
                    piece = f.read(512 * 1024)
                    conn.send(piece)
        conn.close()

    def list_peers_with_file(self, file_name):
        try:
            tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tracker_socket.connect((TRACKER_HOST, TRACKER_PORT))
            tracker_socket.send(f"QUERY {file_name}".encode())
            data = tracker_socket.recv(1024).decode()
            tracker_socket.close()
            if "No peers found" in data:
                print(f"No peers found holding the file '{file_name}'.")
            else:
                print(f"Peers holding '{file_name}': {data}")
        except Exception as e:
            print(f"Error querying peers with file '{file_name}': {e}")

    def download_file(self, file_name):
        tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_socket.connect((TRACKER_HOST, TRACKER_PORT))
        tracker_socket.send(f"REQUEST {file_name}".encode())
        data = tracker_socket.recv(1024).decode()
        tracker_socket.close()

        if "No peers found" in data:
            print(f"No peers found for file '{file_name}'.")
            return

        peers = data.split(',')
        downloader = FileDownloader(file_name, peers, self.repo_path)
        downloader.start()

    def tit_for_tat(self):
        while True:
            time.sleep(10)
            for peer, score in list(self.peer_scores.items()):
                if score < 1:
                    print(f"Disconnecting from free-rider peer {peer}")
                    del self.peer_scores[peer]

    def report_to_tracker(self):
        while True:
            time.sleep(60)  # Mỗi phút gửi báo cáo về tracker
            tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tracker_socket.connect((TRACKER_HOST, TRACKER_PORT))
            tracker_socket.send(f"REPORT {self.host}:{self.port} has files {list(self.shared_files.keys())}".encode())
            tracker_socket.close()

    def communicate_with_neighbors(self):
        while True:
            time.sleep(30)  # Gửi thông tin các pieces có sẵn mỗi 30 giây
            for neighbor in self.neighbors:
                neighbor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                neighbor_socket.connect((neighbor['host'], neighbor['port']))
                for file_name, pieces in self.file_pieces.items():
                    neighbor_socket.send(f"PIECES {file_name} {' '.join(pieces)}".encode())
                neighbor_socket.close()

    def track_peers(self):
        tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tracker_socket.connect((TRACKER_HOST, TRACKER_PORT))
        tracker_socket.send("TRACK".encode())
        neighbors = tracker_socket.recv(1024).decode()
        tracker_socket.close()
        print(f"Connected neighbors: {neighbors}")

if __name__ == "__main__":
    peer_name = input("Enter peer name: ")
    peer = Peer(peer_name, port=0)
    threading.Thread(target=peer.start_server).start()
    threading.Thread(target=peer.tit_for_tat).start()
    threading.Thread(target=peer.track_peers).start()
    threading.Thread(target=peer.report_to_tracker).start()
    threading.Thread(target=peer.communicate_with_neighbors).start()

    while True:
        action = input("Choose action: [find, upload, download, exit]: ").strip().lower()
        if action == "upload":
            file_paths = input("Enter file paths separated by spaces: ").strip()
            peer.upload_files(file_paths)
        elif action == "find":
            file_name = input("Enter file name to find peers: ").strip()
            peer.list_peers_with_file(file_name)
        elif action == "download":
            file_name = input("Enter file name to download: ").strip()
            peer.download_file(file_name)
        elif action == "exit":
            break
