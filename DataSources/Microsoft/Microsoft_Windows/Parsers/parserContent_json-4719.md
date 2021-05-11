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
    """"Hostname"{1,20}:"{1,20}({host}[^",]+)""",
    """"EventTime"{1,20}:"{1,20}({time}[^",]+)""",
    """"SubjectUserName"{1,20}:"{1,20}({user}[^"]+)""",
    """"SubjectDomainName"{1,20}:"{1,20}({domain}[^"]+)""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]+)""",
    """Category:(?:\\t|\\n|\\r|\s)*({audit_category}[^:]+?)(?:\\t|\\n|\\r|\s)*Subcategory:"""
    """Subcategory:(?:\\t|\\n|\\r|\s)*({subcategory}[^:]+?)(?:\\t|\\n|\\r|\s)*Subcategory GUID:""",
    """Changes:(?:\\t)*({policy}[^"]+)""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]+)))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```