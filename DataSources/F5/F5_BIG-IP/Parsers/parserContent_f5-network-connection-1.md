#### Parser Content
```Java
{
Name = f5-network-connection-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ type = irule,""", """,service_id = """, """,client_ip = """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """service_id\s{0,100}=\s{0,100}({service_id}[^,]{1,2000})""",
    """client_ip\s{0,100}=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """client_port\s{0,100}=\s{0,100}({src_port}\d{1,100})""",
  ]
}
```