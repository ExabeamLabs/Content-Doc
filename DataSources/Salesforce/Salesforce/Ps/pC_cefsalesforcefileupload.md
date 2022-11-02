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
  Conditions = [ """attachment-upload""", """destinationServiceName =Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\S+""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\Wsuser=(({domain}[^\\\s@;=]{1,2000})\\+)?(system|({user}[^\\\=\s;@]{1,2000}))\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]{1,2000}?@[^@\s;]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wfname=({file_name}.+?(?:\.({file_ext}[^".]{1,2000}?))?)\s{1,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName =({app}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]


}
```