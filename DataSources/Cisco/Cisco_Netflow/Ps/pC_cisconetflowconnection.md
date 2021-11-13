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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(\S+\s{1,100}){1,2}(\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d(\.\d{1,100})?)\s{1,100}\S+\s{1,100}\S+-6-IPACCESSLOG""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """list \S+ ({outcome}\S+) ({protocol}\S+) ({src_ip}[a-fA-F\d.:]{1,2000})(|\(({src_port}\d{1,100})\)|\s{0,100}({src_interface}\S+))\s{0,100}->\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})(?:\(({dest_port}\d{1,100})\))?""",
    """({packets}\d{1,100})\s{1,100}packets?\s{0,100}$""",
  ]


}
```