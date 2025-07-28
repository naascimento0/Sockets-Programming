"""
Automatic thread and block adjustment system based on file size.
Does not consider hardware or performance metrics - only file size.
"""

import math
import logging

class FileBasedOptimizer:
    """
    Optimizer that adjusts threads and block/chunk sizes based only on file size.
    """
    
    def __init__(self):
        # Base configurations
        self.base_chunk_size = 1024 * 50   # 50KB - default
        self.base_block_size = 1024 * 200  # 200KB - default
        self.min_threads = 2
        self.max_threads = 16
        
        # File size thresholds (in bytes)
        self.file_size_thresholds = {
            'very_small': 1024 * 1024,        # < 1MB
            'small': 10 * 1024 * 1024,        # < 10MB  
            'medium': 100 * 1024 * 1024,      # < 100MB
            'large': 500 * 1024 * 1024,       # < 500MB
            'very_large': 1024 * 1024 * 1024, # < 1GB
            # >= 1GB = huge
        }
        
        logging.info("[FILE OPTIMIZER] Initialized - file size based adjustment")
    
    def get_file_category(self, file_size):
        """Categorizes the file based on size"""
        if file_size < self.file_size_thresholds['very_small']:
            return 'very_small'
        elif file_size < self.file_size_thresholds['small']:
            return 'small'
        elif file_size < self.file_size_thresholds['medium']:
            return 'medium'
        elif file_size < self.file_size_thresholds['large']:
            return 'large'
        elif file_size < self.file_size_thresholds['very_large']:
            return 'very_large'
        else:
            return 'huge'
    
    def get_optimal_threads(self, file_size):
        """Returns the optimal number of threads based on file size"""
        category = self.get_file_category(file_size)
        
        if category == 'very_small':     # < 1MB
            threads = 2
        elif category == 'small':        # 1-10MB
            threads = 3
        elif category == 'medium':       # 10-100MB
            threads = 4
        elif category == 'large':        # 100-500MB
            threads = 6
        elif category == 'very_large':   # 500MB-1GB
            threads = 8
        else:  # huge >= 1GB
            threads = 12
        
        # Ensure it's within limits
        threads = max(self.min_threads, min(self.max_threads, threads))
        
        return threads
    
    def get_optimal_chunk_size(self, file_size):
        """Returns the optimal chunk size based on file size"""
        category = self.get_file_category(file_size)
        
        if category == 'very_small':     # < 1MB
            chunk_size = 1024 * 32       # 32KB
        elif category == 'small':        # 1-10MB
            chunk_size = 1024 * 50       # 50KB (default)
        elif category == 'medium':       # 10-100MB
            chunk_size = 1024 * 64       # 64KB
        elif category == 'large':        # 100-500MB
            chunk_size = 1024 * 128      # 128KB
        elif category == 'very_large':   # 500MB-1GB
            chunk_size = 1024 * 256      # 256KB
        else:  # huge >= 1GB
            chunk_size = 1024 * 512      # 512KB
        
        return chunk_size
    
    def get_optimal_block_size(self, file_size):
        """Returns the optimal block size based on file size"""
        category = self.get_file_category(file_size)
        
        if category == 'very_small':     # < 1MB
            block_size = 1024 * 128      # 128KB
        elif category == 'small':        # 1-10MB
            block_size = 1024 * 200      # 200KB (default)
        elif category == 'medium':       # 10-100MB
            block_size = 1024 * 512      # 512KB
        elif category == 'large':        # 100-500MB
            block_size = 1024 * 1024     # 1MB
        elif category == 'very_large':   # 500MB-1GB
            block_size = 1024 * 1024 * 2 # 2MB
        else:  # huge >= 1GB
            block_size = 1024 * 1024 * 4 # 4MB
        
        return block_size
    
    def get_optimization_info(self, file_size):
        """Returns all optimization information for a file"""
        category = self.get_file_category(file_size)
        threads = self.get_optimal_threads(file_size)
        chunk_size = self.get_optimal_chunk_size(file_size)
        block_size = self.get_optimal_block_size(file_size)
        
        # Calculate number of blocks
        total_blocks = math.ceil(file_size / block_size)
        
        info = {
            'file_size': file_size,
            'file_size_mb': file_size / (1024 * 1024),
            'category': category,
            'threads': threads,
            'chunk_size': chunk_size,
            'chunk_size_kb': chunk_size // 1024,
            'block_size': block_size,
            'block_size_kb': block_size // 1024,
            'total_blocks': total_blocks,
            'chunks_per_block': math.ceil(block_size / chunk_size)
        }
        
        return info
    
    def log_optimization_info(self, file_size, filename=""):
        """Displays optimization information in the log"""
        info = self.get_optimization_info(file_size)
        
        file_desc = f"for {filename} " if filename else ""
        
        logging.info(f"[FILE OPTIMIZER] Optimization {file_desc}({info['file_size_mb']:.1f}MB, category: {info['category']})")
        logging.info(f"[FILE OPTIMIZER] Threads: {info['threads']}, "
                    f"Block: {info['block_size_kb']}KB, "
                    f"Chunk: {info['chunk_size_kb']}KB")
        logging.info(f"[FILE OPTIMIZER] Total blocks: {info['total_blocks']}, "
                    f"Chunks per block: {info['chunks_per_block']}")
        
        return info

# Global optimizer instance
file_optimizer = FileBasedOptimizer()
