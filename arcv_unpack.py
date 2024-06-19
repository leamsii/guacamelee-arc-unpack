import struct
import sys
from ctypes import *
from pathlib import Path
import zlib

class ARCVHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('signature', c_char * 5),
        ('version', c_ubyte),
        ('buffer_size', c_uint32)
    ]

class ARCVTool:
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'rb') as file:
            arcv_header = ARCVHeader()
            file.readinto(arcv_header)

            assert arcv_header.signature == b'ARCV'

            file_names = self.get_file_names(file)
            self.decompressed_buffers(file, file_names)

    def decompressed_buffers(self, file, file_names):
        file.read((len(file_names) * 4) + 8)

        folder_path = Path(Path(self.filename).stem)
        folder_path.mkdir(exist_ok=True)
        print("Log: Created directory " + folder_path.name)
        for name in file_names:
            buffer_header = file.read(9)
            decompressed_size = self.get_decompressed_size(buffer_header)
            buffer_count = self.get_buffer_count(decompressed_size)
            compressed_sizes = self.get_buffer_compressed_sizes(file, buffer_count)
            decompressed_sizes = self.get_buffer_decompressed_sizes(decompressed_size, buffer_count)

            print(f"Log: Unpacking {name}")
            file_data = self.decompress_buffers(file, compressed_sizes, decompressed_sizes)
            file_path = folder_path.joinpath(name)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.touch(exist_ok=True)
            file_path.write_bytes(file_data)


    def decompress_buffers(self, file, compressed_sizes, decompressed_sizes):
        decompressed_buffer = b''
        for compressed_size, decompressed_size in zip(compressed_sizes, decompressed_sizes):
            if compressed_size == 0:
                decompressed_buffer += file.read(decompressed_size)
            else:decompressed_buffer += zlib.decompress(file.read(compressed_size), -15)
        return decompressed_buffer    

    def get_buffer_compressed_sizes(self, file, buffer_count):
        compressed_sizes = []
        for _ in range(buffer_count):
            compressed_sizes.append(struct.unpack('<H', file.read(2))[0])
        return compressed_sizes
    
    def get_buffer_decompressed_sizes(self, overall_decompressed_size, buffer_count):
        decompressed_sizes = []
        for _ in range(buffer_count):
            if overall_decompressed_size < 0x10000:
                decompressed_sizes.append(overall_decompressed_size)
            else:
                decompressed_sizes.append(0x10000)
            overall_decompressed_size -= 0x10000
        return decompressed_sizes

    def get_file_names(self, file):
        buffer_header = file.read(9)
        decompressed_size = self.get_decompressed_size(buffer_header)
        buffer_count = self.get_buffer_count(decompressed_size)
        compressed_sizes = self.get_buffer_compressed_sizes(file, buffer_count)
        decompressed_sizes = self.get_buffer_decompressed_sizes(decompressed_size, buffer_count)
        file_names_buffer = self.decompress_buffers(file, compressed_sizes, decompressed_sizes)

        file_count = struct.unpack('<I', file_names_buffer[0:4])[0]
        file_names = file_names_buffer[file_count + 8:]
        file_names = file_names.split(b'\x00')
        file_names = [name.decode('utf-8') for name in file_names if name]
        return file_names

    def get_buffer_count(self, decompressed_size):
        buffer_count = (decompressed_size >> 16) & 0xFFFF
        if (decompressed_size & 0xFFFF != 0):
            buffer_count += 1
        return buffer_count
    
    def get_decompressed_size(self, buffer):
        buffer_index = 4
        current_byte = buffer[buffer_index]
        decompressed_size = 0
        v7 = 2
        v6 = 1
        v3 = 3

        while v7 - 2 < 0x20:
            v8 = (decompressed_size & ~v6) | ((((1 << v3) & current_byte) != 0) << (v7 - 2))
            if v3 == 7:
                v9 = 0
                buffer_index += 1
                current_byte = buffer[buffer_index]
            else:
                v9 = v3 + 1

            previous_value = v9
            previous_operation = v8
            for i in range(15):
                previous_operation = (((1 << previous_value) & current_byte) != 0) << (v7 + (i - 1)) | previous_operation & ~(v6 << ((i - 1) + 2))
                if previous_value == 7:
                    previous_value = 0
                    buffer_index += 1
                    current_byte = buffer[buffer_index]
                else:
                    previous_value += 1

            decompressed_size = previous_operation
            v7 += 16
            v6 = (v6 << 16) & 0xFFFFFFFF

        return decompressed_size


if __name__ == '__main__':
    filename = sys.argv[1]
    ARCVTool(filename)