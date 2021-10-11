#### Parser Content
```Java
{
Name = pfsense-network-connection-failed
  Vendor = pfSense
  Product = pfSense
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """filterlog:""", """,match,block,""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """filterlog:(?:[^,]{0,2000},){4}({dest_interface}[^,]{0,2000}),({activity}[^,]{0,2000}),({outcome}[^,]{0,2000}),({direction}[^,]{0,2000}),(?:[^,]{0,2000},){8}({protocol}(tcp|udp)),[^,]{0,2000},({src_ip}[^,]{0,2000}),({dest_ip}[^,]{0,2000}),({src_port}[^,]{0,2000}),({dest_port}[^,]{0,2000}),""",
    """filterlog:(?:[^,]{0,2000},){7}in,(?:[^,]{0,2000},){8}(tcp|udp),(?:[^,]{0,2000},){5}({bytes_in}\d{1,100})""",
    """filterlog:(?:[^,]{0,2000},){4}({dest_interface}[^,]{0,2000}),({activity}[^,]{0,2000}),({outcome}[^,]{0,2000}),({direction}[^,]{0,2000}),(?:[^,]{0,2000},){8}({protocol}icmp),[^,]{0,2000},({src_ip}[^,]{0,2000}),({dest_ip}[^,]{0,2000}),"""
  ]
}
```