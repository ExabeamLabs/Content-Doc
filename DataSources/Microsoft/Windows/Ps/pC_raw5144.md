#### Parser Content
```Java
{
Name = raw-5144
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=5144""", """Message=A network share object was deleted.""", """SourceName =Microsoft Windows security auditing""", """Share Name:""", """TaskCategory=File Share""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM))""",
    """EventCode=({event_code}\d{1,100})""",
    """ComputerName =({host}[^\s]{1,2000})""",
    """Keywords=({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """Message=({event_name}[^:]{1,2000}?)\s{1,100}\w+:""",
    """Security ID:\s{1,100}({user_sid}[^:]{1,2000}?)\s{1,100}Account Name:""",
    """Account Name:\s{1,100}({user}[^\s]{1,2000})""",
    """Account Domain:\s{1,100}({domain}[^:]{1,2000}?)\s{1,100}Logon ID:""",
    """Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Share Name:\s{1,100}[\\*]{1,100}({share_name}[^\s]{1,2000})""",
    """Share Path:\s{1,100}({share_path}[^\s]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```