#### Parser Content
```Java
{
Name = cef-salesforce-file-upload
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|resource-uploaded|""", """Sales Cloud""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",
    """([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wsuser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]+?@[^@\s;]+)\s{0,100}(\w+=|$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^".]+?))?)\s{1,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName=({app}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```