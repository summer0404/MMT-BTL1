import socket
import threading

class TrackerServer:
    def __init__(self, host='10.0.175.151', port=65432):
        self.host = host
        self.port = port
        self.files = {}  # Dictionary lưu trữ tên file -> danh sách các peer giữ file đó

    def handle_client(self, conn, addr):
        print(f"New connection from {addr}")
        try:
            while True:
                data = conn.recv(1024).decode()
                if not data:
                    break
                command, *args = data.split()
                response = self.process_command(command, args, addr)
                conn.send(response.encode())
        except ConnectionResetError:
            print(f"Connection reset by peer {addr}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed.")

    def process_command(self, command, args, addr):
        if command == "REGISTER":
            # Đăng ký file từ peer vào danh sách
            peer_address = f"{addr[0]}:{args[0].split(':')[1]}"
            file_name = args[1]
            if file_name in self.files:
                self.files[file_name].add(peer_address)
            else:
                self.files[file_name] = {peer_address}
            return f"File {file_name} registered by {peer_address}"

        elif command == "QUERY":
            # Tìm kiếm các peer giữ file
            file_name = args[0]
            if file_name in self.files:
                peers = ",".join(self.files[file_name])
                return peers
            else:
                return "No peers found"

        elif command == "LIST":
            # Liệt kê tất cả các file trên tracker
            if self.files:
                return "Available files: " + ", ".join(self.files.keys())
            else:
                return "No files available"

        elif command == "TRACK":
            # Trả về danh sách tất cả các file và các peer giữ file
            neighbors = "; ".join(f"{file}: {', '.join(peers)}" for file, peers in self.files.items())
            return neighbors if neighbors else "No files available"

        return "Invalid Command"

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        print(f"Tracker Server running on {self.host}:{self.port}")
        
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    tracker_server = TrackerServer()
    tracker_server.start()
