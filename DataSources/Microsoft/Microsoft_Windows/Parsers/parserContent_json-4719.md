#### Parser Content
```Java
{
Name = json-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4719""", """System audit policy was changed""" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """({event_code}4719)""",
    """"Hostname"+:"+({host}[^",]+)""",
    """"EventTime"+:"+({time}[^",]+)""",
    """"SubjectUserName"+:"+({user}[^"]+)""",
    """"SubjectDomainName"+:"+({domain}[^"]+)""",
    """"SubjectLogonId"+:"+({logon_id}[^"]+)""",
    """Category:(?:\\t|\\n|\\r|\s)*({audit_category}[^:]+?)(?:\\t|\\n|\\r|\s)*Subcategory:"""
    """Subcategory:(?:\\t|\\n|\\r|\s)*({subcategory}[^:]+?)(?:\\t|\\n|\\r|\s)*Subcategory GUID:""",
    """Changes:(?:\\t)*({policy}[^"]+)""",
    """\w+\s*\d+\s*\d+:\d+:\d+\s+(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]+))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```