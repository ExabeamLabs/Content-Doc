#### Parser Content
```Java
{
Name = centrify-remote-logon-2
  Vendor = Centrify
  Product = Centrify Authentication Service
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """SourceName=Centrify AuditTrail""", """AUDIT_TRAIL|Centrify Suite|DirectAuthorize - Windows|""" , """|PowerShell remote connection success|""", """EventCode=6048""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """:\d\d\s\w+\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(?i)(AM|PM))""",
    """ComputerName=({dest_host}[^\.]+)\.({domain}[^\s]+)""",
    """User=(NULL|NOT_TRANSLATED|({user}[^\s]+))""",
    """Sid=({user_sid}[^\s]+?)\sSidType""",
    """EventCode=({event_code}6048)""",
    """AUDIT_TRAIL\|Centrify Suite\|DirectAuthorize - Windows[^=]+?({event_name}PowerShell remote connection success)""",
    """Message:\s*({additional_info}[^:]+)\.\s+""",
  ]
}
```