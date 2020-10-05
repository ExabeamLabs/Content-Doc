#### Parser Content
```Java
{
Name = cisco-netflow-connection
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """6-IPACCESSLOG""", """ packet""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+\s+){1,2}(\w+\s+\d+ \d\d:\d\d:\d\d(\.\d+)?)\s+\S+\s+\S+-6-IPACCESSLOG""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """list \S+ ({outcome}\S+) ({protocol}\S+) ({src_ip}[a-fA-F\d.:]+)(?:\(({src_port}\d+)\)||\s*({src_interface}\S+))\s*->\s*({dest_ip}[a-fA-F\d.:]+)(?:\(({dest_port}\d+)\))?""",
    """({packets}\d+)\s+packets?\s*$""",
  ]
}
```