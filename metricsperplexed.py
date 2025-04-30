
import angr
import claripy
import time
import logging
import psutil
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime

class PerplexedAnalyzer:
    def __init__(self, binary_path="./perplexed"):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.input_len = 27
        self.success_addr = 0x401439
        self.failure_addr = 0x401428
        self.metrics = {
            'execution_time': 0,
            'memory_usage': 0,
            'coverage': 0,
            'visited_blocks': 0,
            'total_blocks': 0,
            'solution_found': False,
            'solution': None,
            'constraints_solved': 0,
            'constraints_total': 0,
            'paths_explored': 0,
            'states_per_second': 0,
            'peak_memory': 0,
            'step_count': 0
        }
        self.setup_logging()

    def setup_logging(self):
        os.makedirs("perplexed_metrics", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"perplexed_metrics/{self.binary_name}_analysis.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("PerplexedAnalyzer")

    def setup_symbolic_input(self):
        input_chars = [claripy.BVS(f'chr_{i}', 8) for i in range(self.input_len)]
        password = claripy.Concat(*input_chars)

        state = self.project.factory.full_init_state(
            stdin=password,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
            }
        )

        for c in input_chars:
            state.solver.add(c >= 0x00)
            state.solver.add(c <= 0x7f)

        return state, password, input_chars

    def calculate_cfg_metrics(self):
        self.logger.info("Generating CFG for perplexed...")
        start_time = time.time()
        cfg = self.project.analyses.CFGFast()
        cfg_time = time.time() - start_time
        self.logger.info(f"CFG generation time: {cfg_time:.2f}s")

        self.metrics['total_blocks'] = len(cfg.graph.nodes())
        return cfg

    def run_analysis(self):
        self.logger.info(f"Starting analysis of {self.binary_name}")
        start_time = time.time()
        process = psutil.Process()
        start_memory = process.memory_info().rss / 1024 / 1024

        cfg = self.calculate_cfg_metrics()
        state, password, input_chars = self.setup_symbolic_input()
        simgr = self.project.factory.simulation_manager(state)

        self.visited_blocks = set()
        self.steps = 0  # <<<< Manual step counter

        time_points = []
        memory_points = []
        states_points = []

        peak_memory = start_memory
        states_tracked = 0
        intervals = []

        def track_performance(simgr):
            nonlocal peak_memory, states_tracked
            self.steps += 1 

            current_memory = process.memory_info().rss / 1024 / 1024
            peak_memory = max(peak_memory, current_memory)
            states_tracked += len(simgr.active)

            current_time = time.time() - start_time
            if not intervals or current_time - intervals[-1] >= 1.0:
                intervals.append(current_time)
                time_points.append(current_time)
                memory_points.append(current_memory)
                states_points.append(states_tracked)

            for state in simgr.active:
                self.visited_blocks.add(state.addr)

            return simgr

        simgr.explore(
            find=self.success_addr,
            avoid=self.failure_addr,
            step_func=track_performance
        )

        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024

        self.metrics['execution_time'] = end_time - start_time
        self.metrics['memory_usage'] = end_memory - start_memory
        self.metrics['peak_memory'] = peak_memory
        self.metrics['visited_blocks'] = len(self.visited_blocks)
        self.metrics['coverage'] = (len(self.visited_blocks) / self.metrics['total_blocks']) * 100 if self.metrics['total_blocks'] > 0 else 0
        self.metrics['step_count'] = self.steps 

        if self.metrics['execution_time'] > 0:
            self.metrics['states_per_second'] = states_tracked / self.metrics['execution_time']

        if len(simgr.found) > 0:
            self.metrics['solution_found'] = True
            found_state = simgr.found[0]
            self.metrics['solution'] = found_state.solver.eval(password, cast_to=bytes)
            self.metrics['constraints_solved'] = len(found_state.solver.constraints)

        self.metrics['constraints_total'] = len(state.solver.constraints)
        self.metrics['paths_explored'] = sum(len(stash) for stash in simgr.stashes.values())

        self.performance_data = {
            'time': time_points,
            'memory': memory_points,
            'states': states_points
        }

        self.logger.info("Analysis completed")
        return self.metrics

    def generate_report(self):
        report_dir = "perplexed_metrics"
        os.makedirs(report_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(report_dir, f"{self.binary_name}_report_{timestamp}.txt")

        self.generate_visualizations(report_dir, timestamp)

        with open(report_file, 'w') as f:
            f.write(f"=== Perplexed Analysis Report ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("=== Performance Metrics ===\n")
            f.write(f"Execution Time: {self.metrics['execution_time']:.2f} seconds\n")
            f.write(f"Memory Usage: {self.metrics['memory_usage']:.2f} MB\n")
            f.write(f"Peak Memory Usage: {self.metrics['peak_memory']:.2f} MB\n")
            f.write(f"States per Second: {self.metrics['states_per_second']:.2f}\n\n")
            f.write("=== Coverage Metrics ===\n")
            f.write(f"Total Basic Blocks: {self.metrics['total_blocks']}\n")
            f.write(f"Visited Basic Blocks: {self.metrics['visited_blocks']}\n")
            f.write(f"Coverage: {self.metrics['coverage']:.2f}%\n\n")
            f.write("=== Symbolic Execution Metrics ===\n")
            f.write(f"Total Steps: {self.metrics['step_count']}\n")
            f.write(f"Paths Explored: {self.metrics['paths_explored']}\n")
            f.write(f"Total Constraints: {self.metrics['constraints_total']}\n")
            f.write(f"Constraints Solved: {self.metrics['constraints_solved']}\n\n")
            f.write("=== Solution ===\n")
            if self.metrics['solution_found']:
                solution_str = self.metrics['solution'].decode('utf-8', errors='replace').strip()
                f.write(f"Solution Found: {solution_str}\n")
            else:
                f.write("No solution found\n")

            f.write("\n=== Visualizations ===\n")
            f.write(f"Coverage chart: coverage_{timestamp}.png\n")
            f.write(f"Performance chart: performance_{timestamp}.png\n")

        self.logger.info(f"Report generated: {report_file}")
        return report_file

    def generate_visualizations(self, report_dir, timestamp):
        plt.figure(figsize=(10, 6))
        labels = ['Covered', 'Uncovered']
        sizes = [self.metrics['visited_blocks'], self.metrics['total_blocks'] - self.metrics['visited_blocks']]
        colors = ['#5cb85c', '#d9534f']
        explode = (0.1, 0)

        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')
        plt.title(f'Code Coverage for {self.binary_name}')
        plt.savefig(f"{report_dir}/coverage_{timestamp}.png")
        plt.close()

        if hasattr(self, 'performance_data'):
            plt.figure(figsize=(10, 6))
            plt.plot(self.performance_data['time'], self.performance_data['memory'], 'b-', label='Memory Usage (MB)')
            plt.plot(self.performance_data['time'], self.performance_data['states'], 'g-', label='States Processed')
            plt.xlabel('Time (s)')
            plt.ylabel('Resources')
            plt.title('Performance Over Time')
            plt.legend()
            plt.grid(True)
            plt.savefig(f"{report_dir}/performance_{timestamp}.png")
            plt.close()

if __name__ == "__main__":
    analyzer = PerplexedAnalyzer()
    analyzer.run_analysis()
    report_file = analyzer.generate_report()

    print(f"\nAnalysis completed! Report saved to: {report_file}")

    print("\nKey Findings:")
    print(f"- Solution Found: {'Yes' if analyzer.metrics['solution_found'] else 'No'}")
    if analyzer.metrics['solution_found']:
        solution_str = analyzer.metrics['solution'].decode('utf-8', errors='replace').strip()
        print(f"- Solution: {solution_str}")
    print(f"- Code Coverage: {analyzer.metrics['coverage']:.2f}%")
    print(f"- Execution Time: {analyzer.metrics['execution_time']:.2f} seconds")
    print(f"- Memory Usage: {analyzer.metrics['memory_usage']:.2f} MB (Peak: {analyzer.metrics['peak_memory']:.2f} MB)")
    print(f"- States per Second: {analyzer.metrics['states_per_second']:.2f}")
    print(f"- Total Steps: {analyzer.metrics['step_count']}")