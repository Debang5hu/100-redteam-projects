#!/usr/bin/env python3
"""
Mouse Cursor Movement Payload - RAW VERSION (No External Dependencies)
Red Team Payload #48 - For educational and authorized testing purposes only

This version directly interfaces with OS APIs using ctypes/native calls.
No pip install required - works with standard Python installation.

Supported: Windows (full), Linux X11 (full), macOS (full)

Author: Manthan Ghasadiya (github.com/manthanghasadiya)
"""

import sys
import time
import random
import math
import argparse


# ============================================================================
# PLATFORM-SPECIFIC CURSOR CONTROL (NO EXTERNAL LIBRARIES)
# ============================================================================

class CursorController:

    def move_to(self, x, y):
        raise NotImplementedError

    def get_position(self):
        raise NotImplementedError

    def get_screen_size(self):
        raise NotImplementedError

    def move_relative(self, dx, dy):
        x, y = self.get_position()
        self.move_to(x + dx, y + dy)


class WindowsCursor(CursorController):
    """
    Windows cursor control using ctypes + user32.dll
    """

    def __init__(self):
        import ctypes
        self.user32 = ctypes.windll.user32

        # Define POINT structure for GetCursorPos
        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        self.POINT = POINT

    def move_to(self, x, y):
        """Move cursor to absolute position using SetCursorPos"""
        self.user32.SetCursorPos(int(x), int(y))

    def get_position(self):
        """Get current cursor position using GetCursorPos"""
        import ctypes
        pt = self.POINT()
        self.user32.GetCursorPos(ctypes.byref(pt))
        return pt.x, pt.y

    def get_screen_size(self):
        """Get screen dimensions using GetSystemMetrics"""
        # SM_CXSCREEN = 0, SM_CYSCREEN = 1
        width = self.user32.GetSystemMetrics(0)
        height = self.user32.GetSystemMetrics(1)
        return width, height


class LinuxX11Cursor(CursorController):
    """
    Linux X11 cursor control using ctypes + libX11.so
    This works on most Linux desktops running X11 (GNOME, KDE, XFCE, etc.)
    Note: Wayland is more restrictive and may not allow this
    """

    def __init__(self):
        import ctypes
        import ctypes.util

        # Load X11 library
        x11_path = ctypes.util.find_library('X11')
        if not x11_path:
            raise OSError("libX11 not found - are you running X11?")

        self.x11 = ctypes.CDLL(x11_path)

        # Open display connection
        self.x11.XOpenDisplay.restype = ctypes.c_void_p
        self.display = self.x11.XOpenDisplay(None)

        if not self.display:
            raise OSError("Cannot open X11 display - is DISPLAY set?")

        # Get default screen and root window
        self.x11.XDefaultScreen.restype = ctypes.c_int
        self.screen = self.x11.XDefaultScreen(self.display)

        self.x11.XRootWindow.restype = ctypes.c_ulong
        self.root = self.x11.XRootWindow(self.display, self.screen)

    def move_to(self, x, y):
        """Move cursor using XWarpPointer"""
        import ctypes
        # XWarpPointer(display, src_window, dest_window, src_x, src_y, src_w, src_h, dest_x, dest_y)
        self.x11.XWarpPointer(
            self.display,
            0,  # src_window (0 = None)
            self.root,  # dest_window (root = absolute position)
            0, 0, 0, 0,  # src_x, src_y, src_width, src_height
            int(x), int(y)  # dest_x, dest_y
        )
        self.x11.XFlush(self.display)

    def get_position(self):
        """Get cursor position using XQueryPointer"""
        import ctypes

        root_return = ctypes.c_ulong()
        child_return = ctypes.c_ulong()
        root_x = ctypes.c_int()
        root_y = ctypes.c_int()
        win_x = ctypes.c_int()
        win_y = ctypes.c_int()
        mask = ctypes.c_uint()

        self.x11.XQueryPointer(
            self.display,
            self.root,
            ctypes.byref(root_return),
            ctypes.byref(child_return),
            ctypes.byref(root_x),
            ctypes.byref(root_y),
            ctypes.byref(win_x),
            ctypes.byref(win_y),
            ctypes.byref(mask)
        )

        return root_x.value, root_y.value

    def get_screen_size(self):
        """Get screen size using XDisplayWidth/Height"""
        width = self.x11.XDisplayWidth(self.display, self.screen)
        height = self.x11.XDisplayHeight(self.display, self.screen)
        return width, height


class MacOSCursor(CursorController):
    """
    macOS cursor control using ctypes + Quartz (CoreGraphics)
    CGEventCreateMouseEvent to generate mouse movement events
    """

    def __init__(self):
        import ctypes
        import ctypes.util

        # Load Quartz framework
        quartz_path = ctypes.util.find_library('Quartz')
        if not quartz_path:
            # Try direct path
            quartz_path = '/System/Library/Frameworks/Quartz.framework/Quartz'

        self.quartz = ctypes.CDLL(quartz_path)

        # Load CoreGraphics for CGMainDisplayID
        cg_path = '/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics'
        self.cg = ctypes.CDLL(cg_path)

        # Define CGPoint structure
        class CGPoint(ctypes.Structure):
            _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

        self.CGPoint = CGPoint

        # Event types
        self.kCGEventMouseMoved = 5

    def move_to(self, x, y):
        """Move cursor using CGEventCreateMouseEvent + CGEventPost"""
        import ctypes

        # Create mouse move event
        point = self.CGPoint(float(x), float(y))

        # CGEventCreateMouseEvent(source, mouseType, mouseCursorPosition, mouseButton)
        self.quartz.CGEventCreateMouseEvent.restype = ctypes.c_void_p
        event = self.quartz.CGEventCreateMouseEvent(
            None,  # source (None = default)
            self.kCGEventMouseMoved,  # mouseType
            point,  # position
            0  # mouseButton (ignored for move)
        )

        # Post the event
        # kCGHIDEventTap = 0
        self.quartz.CGEventPost(0, event)

        # Release event
        self.cg.CFRelease(event)

    def get_position(self):
        """Get cursor position using CGEventGetLocation"""
        import ctypes

        # Create a dummy event to get current position
        self.quartz.CGEventCreate.restype = ctypes.c_void_p
        event = self.quartz.CGEventCreate(None)

        # CGEventGetLocation returns CGPoint
        self.quartz.CGEventGetLocation.restype = self.CGPoint
        point = self.quartz.CGEventGetLocation(event)

        self.cg.CFRelease(event)

        return int(point.x), int(point.y)

    def get_screen_size(self):
        """Get main display size using CGDisplayPixelsWide/High"""
        # Get main display ID
        self.cg.CGMainDisplayID.restype = ctypes.c_uint32
        display_id = self.cg.CGMainDisplayID()

        width = self.cg.CGDisplayPixelsWide(display_id)
        height = self.cg.CGDisplayPixelsHigh(display_id)

        return width, height


def get_cursor_controller():
    """Factory function - returns appropriate controller for current OS"""
    platform = sys.platform

    if platform == 'win32':
        print("[*] Detected Windows - using user32.dll")
        return WindowsCursor()
    elif platform == 'darwin':
        print("[*] Detected macOS - using Quartz/CoreGraphics")
        return MacOSCursor()
    elif platform.startswith('linux'):
        print("[*] Detected Linux - using X11")
        return LinuxX11Cursor()
    else:
        raise OSError(f"Unsupported platform: {platform}")


# ============================================================================
# MOVEMENT PATTERNS (Same as before, but using our raw controller)
# ============================================================================

def random_jitter(cursor, intensity=5, duration=60, interval=0.1):
    """Subtle random movements - simulates hardware malfunction"""
    print(f"[*] Starting random jitter - intensity:{intensity}px, duration:{duration}s")
    end_time = time.time() + duration

    while time.time() < end_time:
        dx = random.randint(-intensity, intensity)
        dy = random.randint(-intensity, intensity)
        cursor.move_relative(dx, dy)
        time.sleep(interval)


def corner_drift(cursor, corner="bottom_right", speed=2, duration=60):
    """Slowly drifts cursor toward a screen corner"""
    width, height = cursor.get_screen_size()

    corners = {
        "top_left": (0, 0),
        "top_right": (width - 1, 0),
        "bottom_left": (0, height - 1),
        "bottom_right": (width - 1, height - 1)
    }

    target_x, target_y = corners.get(corner, corners["bottom_right"])
    print(f"[*] Starting corner drift toward {corner}")

    end_time = time.time() + duration

    while time.time() < end_time:
        current_x, current_y = cursor.get_position()

        dx = 0 if current_x == target_x else (speed if current_x < target_x else -speed)
        dy = 0 if current_y == target_y else (speed if current_y < target_y else -speed)

        if dx != 0 or dy != 0:
            cursor.move_relative(dx, dy)

        time.sleep(0.05)


def circular_motion(cursor, radius=100, speed=0.05, duration=60):
    """Moves cursor in a circular pattern"""
    print(f"[*] Starting circular motion - radius:{radius}px")

    center_x, center_y = cursor.get_position()
    angle = 0
    end_time = time.time() + duration
    width, height = cursor.get_screen_size()

    while time.time() < end_time:
        x = center_x + int(radius * math.cos(angle))
        y = center_y + int(radius * math.sin(angle))

        # Keep within screen bounds
        x = max(0, min(x, width - 1))
        y = max(0, min(y, height - 1))

        cursor.move_to(x, y)
        angle += 0.1
        time.sleep(speed)


def evasion_mode(cursor, trigger_distance=50, jump_distance=200, duration=60):
    """Cursor jumps away when user tries to move it"""
    print(f"[*] Starting evasion mode")

    last_x, last_y = cursor.get_position()
    end_time = time.time() + duration
    width, height = cursor.get_screen_size()

    while time.time() < end_time:
        current_x, current_y = cursor.get_position()

        distance_moved = math.sqrt((current_x - last_x) ** 2 + (current_y - last_y) ** 2)

        if distance_moved > trigger_distance:
            angle = random.uniform(0, 2 * math.pi)
            new_x = current_x + int(jump_distance * math.cos(angle))
            new_y = current_y + int(jump_distance * math.sin(angle))

            new_x = max(0, min(new_x, width - 1))
            new_y = max(0, min(new_y, height - 1))

            cursor.move_to(new_x, new_y)
            current_x, current_y = new_x, new_y

        last_x, last_y = current_x, current_y
        time.sleep(0.02)


def drunk_cursor(cursor, wobble=30, duration=60):
    """Cursor appears 'drunk' - wobbly movements"""
    print(f"[*] Starting drunk cursor mode")

    end_time = time.time() + duration

    while time.time() < end_time:
        if random.random() < 0.1:
            dx = random.randint(-wobble * 2, wobble * 2)
            dy = random.randint(-wobble * 2, wobble * 2)
        else:
            dx = random.randint(-wobble // 2, wobble // 2)
            dy = random.randint(-wobble // 2, wobble // 2)

        cursor.move_relative(dx, dy)
        time.sleep(random.uniform(0.05, 0.2))


def gravity_pull(cursor, strength=0.05, duration=60):
    """Cursor constantly pulled toward screen center"""
    width, height = cursor.get_screen_size()
    target_x, target_y = width // 2, height // 2

    print(f"[*] Starting gravity pull toward center ({target_x}, {target_y})")

    end_time = time.time() + duration

    while time.time() < end_time:
        current_x, current_y = cursor.get_position()

        dx = int((target_x - current_x) * strength)
        dy = int((target_y - current_y) * strength)

        if dx != 0 or dy != 0:
            cursor.move_relative(dx, dy)

        time.sleep(0.02)


def chaos_mode(cursor, duration=60):
    """Randomly switches between patterns"""
    print("[*] Starting chaos mode")

    patterns = [
        lambda: random_jitter(cursor, intensity=10, duration=5),
        lambda: corner_drift(cursor, corner=random.choice(["top_left", "top_right", "bottom_left", "bottom_right"]),
                             duration=5),
        lambda: circular_motion(cursor, radius=random.randint(50, 150), duration=5),
        lambda: drunk_cursor(cursor, wobble=random.randint(20, 50), duration=5),
    ]

    end_time = time.time() + duration

    while time.time() < end_time:
        pattern = random.choice(patterns)
        try:
            pattern()
        except Exception:
            pass


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Mouse Cursor Payload - RAW VERSION (No Dependencies)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This version uses direct OS API calls:
  - Windows: user32.dll SetCursorPos/GetCursorPos
  - Linux:   libX11.so XWarpPointer/XQueryPointer  
  - macOS:   Quartz CGEventCreateMouseEvent

No pip install required - pure Python + ctypes!

Examples:
  python mouse_mover_raw.py --mode jitter --duration 30
  python mouse_mover_raw.py --mode evasion --duration 60
        """
    )

    parser.add_argument(
        "--mode", "-m",
        choices=["jitter", "drift", "circle", "evasion", "drunk", "gravity", "chaos"],
        default="jitter",
        help="Movement pattern (default: jitter)"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=60,
        help="Duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--intensity", "-i",
        type=int,
        default=5,
        help="Movement intensity in pixels (default: 5)"
    )

    args = parser.parse_args()

    try:
        cursor = get_cursor_controller()
    except OSError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    width, height = cursor.get_screen_size()

    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║   Mouse Cursor Payload - RAW (No Dependencies)   ║
    ║         github.com/manthanghasadiya              ║
    ╚══════════════════════════════════════════════════╝

    [*] Platform: {sys.platform}
    [*] Mode: {args.mode}
    [*] Duration: {args.duration}s
    [*] Screen: {width}x{height}
    [*] Starting in 3 seconds... (Ctrl+C to abort)
    """)

    time.sleep(3)

    try:
        if args.mode == "jitter":
            random_jitter(cursor, intensity=args.intensity, duration=args.duration)
        elif args.mode == "drift":
            corner_drift(cursor, duration=args.duration)
        elif args.mode == "circle":
            circular_motion(cursor, duration=args.duration)
        elif args.mode == "evasion":
            evasion_mode(cursor, duration=args.duration)
        elif args.mode == "drunk":
            drunk_cursor(cursor, wobble=args.intensity * 6, duration=args.duration)
        elif args.mode == "gravity":
            gravity_pull(cursor, duration=args.duration)
        elif args.mode == "chaos":
            chaos_mode(cursor, duration=args.duration)

        print("\n[+] Payload execution completed")

    except KeyboardInterrupt:
        print("\n[!] Payload interrupted by user")


if __name__ == "__main__":
    main()