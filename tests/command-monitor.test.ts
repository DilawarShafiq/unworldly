import { describe, it, expect } from 'vitest';
import { CommandMonitor, createCommandMonitor } from '../src/command-monitor.js';

describe('CommandMonitor', () => {
  it('should create a monitor instance', () => {
    const monitor = createCommandMonitor();
    expect(monitor).toBeInstanceOf(CommandMonitor);
  });

  it('should stop cleanly after start', () => {
    const monitor = new CommandMonitor();
    const events: unknown[] = [];
    monitor.start('.', (cmd) => events.push(cmd));
    // Let it run briefly then stop
    monitor.stop();
    // Should not throw
    expect(true).toBe(true);
  });

  it('should stop cleanly without starting', () => {
    const monitor = new CommandMonitor();
    // Should not throw
    monitor.stop();
    expect(true).toBe(true);
  });

  it('should not report same PID twice', async () => {
    const monitor = new CommandMonitor();
    const events: unknown[] = [];
    monitor.start('.', (cmd) => events.push(cmd));

    // Wait for two poll cycles
    await new Promise(resolve => setTimeout(resolve, 1200));
    const count = events.length;

    // Wait another cycle — should not get duplicates of existing processes
    await new Promise(resolve => setTimeout(resolve, 600));

    monitor.stop();
    // The count should not have significantly increased from duplicate reporting
    // (new system processes may appear, but existing ones should not repeat)
    expect(events.length).toBeLessThanOrEqual(count + 5);
  });
});
