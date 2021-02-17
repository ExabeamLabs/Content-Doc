#### Parser Content
```Java
{
Name = palo-alto-file-operations
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""activity_monitoring""",""" Aperture """,""",file,"""]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s({host}[^\s]+)""",
    """activity_monitoring,"?({app}[^,"]+)""",
    ""","*\s*({file_name}[^,"]+?(\.\s*({file_ext}[^\.",]+?))?)"*,file""",
    """activity_monitoring,"*([^,]*,){5}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,file,"*([\w\s]+|({user_email}[^@]+@[^",]+))"*,({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,({accesses}[^,]+),(|[^,]),file"""
    """,file,"*([\w\s]+|([^@]+@[^",]+))"*,([A-Fa-f.\d:]+),\w+,({accesses}[\w]+)"*,""",
    """,file,"*([\w\s]+|([^@]+@[^",]+))"*,([A-Fa-f.\d:]+),"+[^"]+"+,({accesses}[\w]+)"*,""",
   ]
}
```