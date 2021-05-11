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
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}The Windows Filtering Platform has blocked a connection)""",
    """Process ID:\s{1,100}({pid}[^\s]+)\s{1,100}Application""",
    """Direction:\s{1,100}({direction}[^\s]+)\s{1,100}Source Address:""",
    """Source Address:\s{1,100}({src_ip}[a-fA-F\d:\.]+)""",
    """Source Port:\s{1,100}({src_port}\d{1,100})""",
    """Destination Address:\s{1,100}({dest_ip}[a-fA-F\d:\.]+)""",
    """Destination Port:\s{1,100}({dest_port}\d{1,100})"""
  ]
}
```