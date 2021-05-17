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
    """"Hostname"{1,20}:"{1,20}({host}[^",]{1,2000})""",
    """"EventTime"{1,20}:"{1,20}({time}[^",]{1,2000})""",
    """"SubjectUserName"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"SubjectDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """Category:(?:\\t|\\n|\\r|\s)*({audit_category}[^:]{1,2000}?)(?:\\t|\\n|\\r|\s)*Subcategory:"""
    """Subcategory:(?:\\t|\\n|\\r|\s)*({subcategory}[^:]{1,2000}?)(?:\\t|\\n|\\r|\s)*Subcategory GUID:""",
    """Changes:(?:\\t)*({policy}[^"]{1,2000})""",
    """(?i)\w+\s{0,100}\d{1,100}\s{0,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(::ffff:)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(am|pm|({dest_host}[\w\-.]{1,2000})))"""
  ]
  DupFields = [ "host->dest_host" ]
}
```