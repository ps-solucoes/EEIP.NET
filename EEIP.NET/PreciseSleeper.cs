using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Sres.Net.EEIP
{
    /// <summary>
    /// Sleeps with sub-millisecond resolution. Thread.Sleep and WaitOne only take whole milliseconds and on Windows
    /// round up to the timer tick (15.6 ms by default), which is useless for packet rates of a few milliseconds.
    /// Windows: a high-resolution waitable timer (Windows 10 1803 and later). Linux/macOS: nanosleep.
    /// Not thread safe: one instance per thread.
    /// </summary>
    internal sealed class PreciseSleeper : IDisposable
    {
        private IntPtr timer;

        /// <summary>false where no high-resolution sleep is available (Windows before 1803): Sleep must not be called</summary>
        public bool IsPrecise { get; }

        public PreciseSleeper()
        {
            if (OperatingSystem.IsWindows())
            {
                timer = CreateWaitableTimerExW(IntPtr.Zero, IntPtr.Zero, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
                IsPrecise = timer != IntPtr.Zero;
            }
            else
                IsPrecise = OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD();
        }

        /// <summary>Sleeps for about <paramref name="ticks"/> (<see cref="Stopwatch"/> ticks); may return early (signal) or a little late</summary>
        public void Sleep(long ticks)
        {
            if (ticks <= 0)
                return;
            if (OperatingSystem.IsWindows())
            {
                long dueTime = -Math.Max(1, (long)(ticks * (10_000_000.0 / Stopwatch.Frequency)));     //Relative, in 100 ns units
                if (SetWaitableTimer(timer, ref dueTime, 0, IntPtr.Zero, IntPtr.Zero, 0) != 0)
                    WaitForSingleObject(timer, INFINITE);
            }
            else
            {
                long nanoseconds = (long)(ticks * (1_000_000_000.0 / Stopwatch.Frequency));
                Timespec request = new Timespec { Seconds = (nint)(nanoseconds / 1_000_000_000), Nanoseconds = (nint)(nanoseconds % 1_000_000_000) };
                nanosleep(ref request, IntPtr.Zero);       //EINTR just ends the sleep early, the caller checks the time anyway
            }
        }

        public void Dispose()
        {
            if (timer != IntPtr.Zero)
            {
                CloseHandle(timer);
                timer = IntPtr.Zero;
            }
        }

        private const uint CREATE_WAITABLE_TIMER_HIGH_RESOLUTION = 0x00000002;
        private const uint TIMER_ALL_ACCESS = 0x001F0003;
        private const uint INFINITE = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        private struct Timespec
        {
            public nint Seconds;
            public nint Nanoseconds;
        }

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr CreateWaitableTimerExW(IntPtr timerAttributes, IntPtr timerName, uint flags, uint desiredAccess);

        [DllImport("kernel32", SetLastError = true)]
        private static extern int SetWaitableTimer(IntPtr timer, ref long dueTime, int period, IntPtr completionRoutine, IntPtr argToCompletionRoutine, int resume);

        [DllImport("kernel32", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32", SetLastError = true)]
        private static extern int CloseHandle(IntPtr handle);

        [DllImport("libc", SetLastError = true)]
        private static extern int nanosleep(ref Timespec request, IntPtr remaining);
    }
}
