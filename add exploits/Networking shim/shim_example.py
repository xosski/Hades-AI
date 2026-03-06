"""
Example usage of the SermonShim API
"""

from shim import create_shim, SermonShim
import logging

logging.basicConfig(level=logging.INFO)


def example_bit_processing():
    """Example: Process binary data with bit stuffing"""
    print("\n=== Bit Processing Example ===")
    shim = create_shim()
    
    binary_data = "11111000111"
    result = shim.process_data('bit', binary_data)
    print(f"Input:  {binary_data}")
    print(f"Output: {result}")


def example_checksum():
    """Example: Calculate checksum"""
    print("\n=== Checksum Example ===")
    shim = create_shim()
    
    binary_data = "1101001101"
    result = shim.process_data('checksum', binary_data)
    print(f"Input:  {binary_data}")
    print(f"Checksum: {result}")


def example_hamming_code():
    """Example: Generate Hamming code"""
    print("\n=== Hamming Code Example ===")
    shim = create_shim()
    
    binary_data = "1010"
    result = shim.process_data('hamming', binary_data)
    print(f"Input:  {binary_data}")
    print(f"Hamming Code: {result}")


def example_network_tcp():
    """Example: TCP communication"""
    print("\n=== TCP Network Example ===")
    shim = create_shim()
    
    # This would connect to an actual TCP server
    # shim.send_over_network('TCP', 'localhost', 5000, 'Hello Server')
    # response = shim.receive_from_network('TCP')
    
    print("TCP setup configured (requires actual server)")


def example_monitoring():
    """Example: Monitor system status"""
    print("\n=== Monitoring Example ===")
    shim = create_shim()
    
    # Set status
    shim.status_monitor.set_status("running")
    shim.status_monitor.set_metric("cpu_usage", 45.2)
    shim.status_monitor.set_metric("memory_usage", 62.8)
    
    # Add incident
    shim.incident_monitor.add_incident({
        "id": "INC001",
        "subject": "Data quality issue detected",
        "state": "open",
        "severity": "high"
    })
    
    # Get report
    print(shim.get_status_report())


def example_combined_workflow():
    """Example: Combined workflow using multiple subsystems"""
    print("\n=== Combined Workflow Example ===")
    shim = create_shim()
    
    # 1. Process data
    print("Step 1: Processing binary data...")
    binary_data = "11110000"
    processed = shim.process_data('bit', binary_data)
    print(f"  Original: {binary_data}")
    print(f"  Processed: {processed}")
    
    # 2. Update monitoring
    print("Step 2: Updating system status...")
    shim.status_monitor.set_status("processing")
    shim.status_monitor.set_metric("last_operation", "bit_stuffing")
    
    # 3. Report
    print("Step 3: Status report")
    print(f"  {shim.get_status_report()}")


if __name__ == "__main__":
    print("SermonShim Usage Examples")
    print("=" * 50)
    
    example_bit_processing()
    example_checksum()
    example_hamming_code()
    example_network_tcp()
    example_monitoring()
    example_combined_workflow()
    
    print("\n" + "=" * 50)
    print("Examples completed")
