#### Parser Content
```Java
{
Name = raw-5142
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName =Microsoft Windows security auditing""", """A network share object was added""", """EventCode=5142""", """Share Information:""" ]
  Fields = [
    """ComputerName =({host}[\w\-.]{1,2000})""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}(am|AM|pm|PM))""",
    """({event_name}A network share object was added)""",
    """({event_code}5142)""",
    """Account Name:\s{0,100}({user}[^\s]{1,2000})""",
    """Account Domain:\s{0,100}({domain}[^\s]{1,2000})""",
    """Logon ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """Security ID:\s{0,100}(NT|({user_sid}[^\s]{1,2000}))""",
    """Share Name:\s{0,100}[\\\*]{0,2000}({share_name}[^:]{1,2000}?)\s{0,100}Share Path:""",
    """Share Path:\s{0,100}(\s|({share_path}[^"]{1,2000}?))\s{0,100}$""",
    """Keywords=({outcome}[^:=]{1,2000}?)\s{0,100}\w{1,2000}[:=]"""
  ]
  DupFields = [ "host->dest_host" ]


}
```