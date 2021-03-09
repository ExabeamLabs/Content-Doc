#### Parser Content
```Java
{
Name = cef-salesforce-file-download
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|resource-downloaded|""", """Sales Cloud""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",
    """([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wsuser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]+?@[^@\s;]+)\s*(\w+=|$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^".]+?))?)\s+(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s+(\w+=|$)""",
    """\WdestinationServiceName=({app}.+?)\s*(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```