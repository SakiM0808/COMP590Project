
import angr
import claripy
import time
import logging
import psutil
import matplotlib.pyplot as plt
import os
from datetime import datetime

class Crackme100Analyzer:
    def __init__(self, binary_path="./crackme100"):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.input_len = 50  # Based on your crackme100angr.py
        self.success_addr = 0x401378  # Target address
        self.failure_addr = 0x401389  # Avoid address
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
            'deadended_paths': 0,
            'active_paths': 0
        }
        self.setup_logging()

    def setup_logging(self):
        os.makedirs("crackme100_metrics", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f"crackme100_metrics/{self.binary_name}_analysis.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("Crackme100Analyzer")

    def setup_symbolic_input(self):
        flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(self.input_len)]
        flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

        state = self.project.factory.full_init_state(
            stdin=flag,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
            }
        )

        for k in flag_chars:
            state.solver.add(k >= 0x20)
            state.solver.add(k <= 0x7e)

        return state, flag, flag_chars

    def calculate_cfg_metrics(self):
        self.logger.info("Generating CFG for crackme100...")
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
        state, flag, flag_chars = self.setup_symbolic_input()
        simgr = self.project.factory.simulation_manager(state)

        self.visited_blocks = set()
        self.steps = 0  # <=== MANUAL step counter
        exploration_checkpoints = []

        def step_func(simgr):
            self.steps += 1
            if len(exploration_checkpoints) == 0 or exploration_checkpoints[-1]['steps'] + 5 <= self.steps:
                exploration_checkpoints.append({
                    'steps': self.steps,
                    'time': time.time() - start_time,
                    'active': len(simgr.active),
                    'deadended': len(simgr.deadended) if 'deadended' in simgr.stashes else 0,
                    'found': len(simgr.found) if 'found' in simgr.stashes else 0
                })

            for state in simgr.active:
                self.visited_blocks.add(state.addr)

            return simgr

        simgr.explore(
            find=self.success_addr,
            avoid=self.failure_addr,
            step_func=step_func
        )

        end_time = time.time()
        end_memory = process.memory_info().rss / 1024 / 1024

        self.metrics['execution_time'] = end_time - start_time
        self.metrics['memory_usage'] = end_memory - start_memory
        self.metrics['visited_blocks'] = len(self.visited_blocks)
        self.metrics['coverage'] = (len(self.visited_blocks) / self.metrics['total_blocks']) * 100 if self.metrics['total_blocks'] > 0 else 0

        if len(simgr.found) > 0:
            self.metrics['solution_found'] = True
            found_state = simgr.found[0]
            self.metrics['solution'] = found_state.solver.eval(flag, cast_to=bytes)
            self.metrics['constraints_solved'] = len(found_state.solver.constraints)

        self.metrics['constraints_total'] = len(state.solver.constraints)
        self.metrics['paths_explored'] = sum(len(stash) for stash in simgr.stashes.values())
        self.metrics['deadended_paths'] = len(simgr.deadended) if 'deadended' in simgr.stashes else 0
        self.metrics['active_paths'] = len(simgr.active) if 'active' in simgr.stashes else 0

        self.exploration_progress = exploration_checkpoints
        self.logger.info("Analysis completed")
        return self.metrics

    def generate_report(self):
        report_dir = "crackme100_metrics"
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(report_dir, f"{self.binary_name}_report_{timestamp}.txt")

        self.generate_visualizations(report_dir, timestamp)

        with open(report_file, 'w') as f:
            f.write(f"=== Crackme100 Analysis Report ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("=== Performance Metrics ===\n")
            f.write(f"Execution Time: {self.metrics['execution_time']:.2f} seconds\n")
            f.write(f"Memory Usage: {self.metrics['memory_usage']:.2f} MB\n\n")
            
            f.write("=== Coverage Metrics ===\n")
            f.write(f"Total Basic Blocks: {self.metrics['total_blocks']}\n")
            f.write(f"Visited Basic Blocks: {self.metrics['visited_blocks']}\n")
            f.write(f"Coverage: {self.metrics['coverage']:.2f}%\n\n")
            
            f.write("=== Symbolic Execution Metrics ===\n")
            f.write(f"Paths Explored: {self.metrics['paths_explored']}\n")
            f.write(f"Deadended Paths: {self.metrics['deadended_paths']}\n")
            f.write(f"Active Paths: {self.metrics['active_paths']}\n")
            f.write(f"Total Constraints: {self.metrics['constraints_total']}\n")
            f.write(f"Constraints Solved: {self.metrics['constraints_solved']}\n\n")
            
            f.write("=== Solution ===\n")
            if self.metrics['solution_found']:
                solution_str = self.metrics['solution'].decode('utf-8', errors='replace').strip()
                f.write(f"Solution Found: {solution_str}\n")
                has_upper = any(c.isupper() for c in solution_str)
                has_lower = any(c.islower() for c in solution_str)
                has_digit = any(c.isdigit() for c in solution_str)
                has_special = any(not c.isalnum() for c in solution_str)
                password_complexity = sum([has_upper, has_lower, has_digit, has_special])
                f.write(f"Password Complexity (0-4): {password_complexity}\n")
                f.write(f"Password Length: {len(solution_str)}\n")
            else:
                f.write("No solution found\n")
            
            f.write("\n=== Visualization ===\n")
            f.write(f"Coverage chart saved to: {report_dir}/coverage_{timestamp}.png\n")
            f.write(f"Performance chart saved to: {report_dir}/performance_{timestamp}.png\n")
            f.write(f"Exploration progress saved to: {report_dir}/exploration_{timestamp}.png\n")

        self.logger.info(f"Report generated: {report_file}")
        return report_file

    def generate_visualizations(self, report_dir, timestamp):
        plt.figure(figsize=(10, 6))
        labels = ['Covered', 'Uncovered']
        sizes = [self.metrics['visited_blocks'],
                 self.metrics['total_blocks'] - self.metrics['visited_blocks']]
        colors = ['#66b3ff', '#c2c2c2']
        explode = (0.1, 0)

        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')
        plt.title(f'Code Coverage for {self.binary_name}')
        plt.savefig(f"{report_dir}/coverage_{timestamp}.png")
        plt.close()

        labels = ['Execution Time (s)', 'Memory Usage (MB)']
        values = [self.metrics['execution_time'], self.metrics['memory_usage']]

        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, values, color=['#66b3ff', '#99ff99'])

        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                     f'{height:.2f}', ha='center', va='bottom')

        plt.title(f'Performance Metrics for {self.binary_name}')
        plt.tight_layout()
        plt.savefig(f"{report_dir}/performance_{timestamp}.png")
        plt.close()

        if hasattr(self, 'exploration_progress') and self.exploration_progress:
            plt.figure(figsize=(12, 6))
            steps = [cp['steps'] for cp in self.exploration_progress]
            active = [cp['active'] for cp in self.exploration_progress]
            deadended = [cp['deadended'] for cp in self.exploration_progress]
            found = [cp['found'] for cp in self.exploration_progress]

            plt.plot(steps, active, 'b-', label='Active Paths')
            plt.plot(steps, deadended, 'r-', label='Deadended Paths')
            plt.plot(steps, found, 'g-', label='Found Paths')

            plt.xlabel('Steps')
            plt.ylabel('Path Count')
            plt.title('Symbolic Execution Progress')
            plt.legend()
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(f"{report_dir}/exploration_{timestamp}.png")
            plt.close()


if __name__ == "__main__":
    analyzer = Crackme100Analyzer()
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
    print(f"- Memory Usage: {analyzer.metrics['memory_usage']:.2f} MB")
    print(f"- Total Paths Explored: {analyzer.metrics['paths_explored']}")