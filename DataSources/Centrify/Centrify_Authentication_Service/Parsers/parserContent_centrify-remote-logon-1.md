#### Parser Content
```Java
{
Name = centrify-remote-logon-1
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|DirectAuthorize - Windows|""" , """|Remote login success|""", """EventCode=6033""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """entityname=({domain}[^\\]+)\\({dest_host}[^\s]+)""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]+))""",
    """Sid=({user_sid}[^\s]+?)\sSidType""",
    """EventCode=({event_code}6033)""",
    """AUDIT_TRAIL\|Centrify Suite\|DirectAuthorize - Windows[^=]+?({event_name}Remote login success)""",
    """Message:\s*({additional_info}[^:]+)\.\s+""",
  ]
}
```