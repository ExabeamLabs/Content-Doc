#### Parser Content
```Java
{
Name = apc-remote-logon
  Vendor = APC
  Product = APC
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """ Web user """, """ logged in from """ ]
  Fields = [
    """<\d{1,100}>(\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d)\s{1,100}({host}[\w.\-]+)\s""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Web user '({user}[^']+)'""",
    """\slogged in from ({src_ip}[a-fA-F\d.:]+?)\.?\s{1,100}"""
  ]
  DupFields = [ "host->dest_host" ]
}
```