import hashlib
import json
import os

class MetainfoFile:
    def __init__(self, file_path, tracker_address, piece_length=512 * 1024):
        self.file_path = file_path
        self.tracker_address = tracker_address
        self.piece_length = piece_length
        self.pieces = []
        self.create_pieces()

    def create_pieces(self):
        # Đọc file và tạo các phần (pieces)
        with open(self.file_path, 'rb') as f:
            while True:
                piece = f.read(self.piece_length)
                if not piece:
                    break
                piece_hash = hashlib.sha1(piece).hexdigest()
                self.pieces.append(piece_hash)

    def to_dict(self):
        return {
            'tracker_address': self.tracker_address,
            'piece_length': self.piece_length,
            'piece_count': len(self.pieces),
            'pieces': self.pieces,
            'file_name': os.path.basename(self.file_path)
        }

    def save(self):
        # Lưu metainfo dưới dạng JSON
        metainfo_path = f"{self.file_path}.torrent"
        with open(metainfo_path, 'w') as f:
            json.dump(self.to_dict(), f)
        print(f"Metainfo file created at {metainfo_path}")

class MagnetText:
    @staticmethod
    def generate_magnet_link(file_path):
        # Tạo mã hash SHA-1 từ metainfo file để tạo link magnet
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha1(file_data).hexdigest()
        return f"magnet:?xt=urn:btih:{file_hash}"
