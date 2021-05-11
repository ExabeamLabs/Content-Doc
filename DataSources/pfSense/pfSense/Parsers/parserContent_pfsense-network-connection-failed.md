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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """filterlog:(?:[^,]*,){4}({dest_interface}[^,]*),({activity}[^,]*),({outcome}[^,]*),({direction}[^,]*),(?:[^,]*,){8}({protocol}(tcp|udp)),[^,]*,({src_ip}[^,]*),({dest_ip}[^,]*),({src_port}[^,]*),({dest_port}[^,]*),""",
    """filterlog:(?:[^,]*,){7}in,(?:[^,]*,){8}(tcp|udp),(?:[^,]*,){5}({bytes_in}\d{1,100})""",
    """filterlog:(?:[^,]*,){4}({dest_interface}[^,]*),({activity}[^,]*),({outcome}[^,]*),({direction}[^,]*),(?:[^,]*,){8}({protocol}icmp),[^,]*,({src_ip}[^,]*),({dest_ip}[^,]*),"""
  ]
}
```