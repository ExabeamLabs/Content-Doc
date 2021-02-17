#### Parser Content
```Java
{
Name = f5-network-connection-1
  Vendor = F5
  Product = IRULE F5
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ type = irule,""", """,service_id = """, """,client_ip = """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """service_id\s*=\s*({service_id}[^,]+)""",
    """client_ip\s*=\s*({src_ip}[A-Fa-f:\d.]+)""",
    """client_port\s*=\s*({src_port}\d+)""",
  ]
}
```