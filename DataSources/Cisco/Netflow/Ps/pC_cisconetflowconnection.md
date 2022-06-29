#### Parser Content
```Java
{
Name = cisco-netflow-connection
  Vendor = Cisco
  Product = Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """6-IPACCESSLOG""", """ packet""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}(\S+\s{1,100}){1,2}(\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d(\.\d{1,100})?)\s{1,100}\S+\s{1,100}\S+-6-IPACCESSLOG""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\slist\s\S{1,2000}\s({outcome}\S{1,2000})\s(|({protocol}[^\.:]{1,2000})\s)?({src_ip}[a-fA-F\d.:]{1,2000})\s{0,20}(\(({src_port}\d{1,5})\))?(\s(|({src_interface}\S{1,2000})))?(->\s({dest_ip}[a-fA-F\d:.]{1,2000})(\(({dest_port}\d{1,5})\)|\s\([^\)]{1,2000}\))?,\s)?\d{1,20}\spacket""",
    """({packets}\d{1,100})\s{1,100}packets?\s{0,100}$"""
  ]


}
```