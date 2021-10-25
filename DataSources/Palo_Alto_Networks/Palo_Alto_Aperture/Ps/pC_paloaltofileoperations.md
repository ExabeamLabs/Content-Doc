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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """activity_monitoring,"?({app}[^,"]{1,2000})""",
    ""","{0,20}\s{0,100}({file_name}[^,"]{1,2000}?(\.\s{0,100}({file_ext}[^\.",]{1,2000}?))?)"{0,20},file""",
    """activity_monitoring,"{0,20}([^,]{0,2000},){5}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,file,"{0,20}([\w\s]{1,2000}|({user_email}[^@]{1,2000}@[^",]{1,2000}))"{0,20},({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,({accesses}[^,]{1,2000}),(|[^,]),file"""
    """,file,"{0,20}([\w\s]{1,2000}|([^@]{1,2000}@[^",]{1,2000}))"{0,20},([A-Fa-f.\d:]{1,2000}),\w+,({accesses}[\w]{1,2000})"{0,20},""",
    """,file,"{0,20}([\w\s]{1,2000}|([^@]{1,2000}@[^",]{1,2000}))"{0,20},([A-Fa-f.\d:]{1,2000}),"{1,20}[^"]{1,2000}"{1,20},({accesses}[\w]{1,2000})"{0,20},""",
   ]
}
```