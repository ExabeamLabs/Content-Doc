#### Parser Content
```Java
{
Name = raw-5157-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "process-network-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Layer Name:""", """The Windows Filtering Platform has blocked a connection""", """Network Information:""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """Process ID:\s+({pid}[^\s]+)\s+Application""",
    """Direction:\s+({direction}[^\s]+)\s+Source Address:""",
    """Source Address:\s+({src_ip}[a-fA-F\d:\.]+)""",
    """Source Port:\s+({src_port}\d+)""",
    """Destination Address:\s+({dest_ip}[a-fA-F\d:\.]+)""",
    """Destination Port:\s+({dest_port}\d+)"""
  ]
}
```