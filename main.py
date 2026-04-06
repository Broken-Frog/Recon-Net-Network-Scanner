# main.py
from backend.scan_manager import start_network_scan
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_pcap>")
        print("Example: python main.py samples/DoS-GoldenEye_attack.pcap")
        sys.exit(1)

    file_path = sys.argv[1]
    
    result = start_network_scan(file_path)
    
    if result is None:
        print("❌ Error: Scan function returned None. Check scan_manager.py")
        sys.exit(1)
    
    if isinstance(result, dict) and "error" in result:
        print(f"❌ Scan Error: {result['error']}")
    else:
        print("\n🎉 Scan completed successfully!")
