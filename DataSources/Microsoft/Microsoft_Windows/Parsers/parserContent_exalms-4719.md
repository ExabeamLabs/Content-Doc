#### Parser Content
```Java
{
Name = exalms-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":4719""", """System audit policy was changed.""", """"@timestamp"""" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s*:\s*"({host}.+?)"""",
    """"event_id"\s*:\s*({event_code}\d+)""",
    """"(SubjectUserName)"\s*:\s*"({user}.+?)\s*"""",
    """"(SubjectDomainName)"\s*:\s*"({domain}.+?)\s*"""",
    """"(SubjectLogonId|logon_id)"\s*:\s*"({logon_id}.+?)\s*"""",
    """(\\t|\\n|\s)Category:(\\t|\\n|\s)*({audit_category}.+?)(\\t|\\n|\s)+Subcategory:""",
    """(\\t|\\n|\s)Subcategory:(\\t|\\n|\s)*({subcategory}.+?)(\\t|\\n|\s)+Subcategory GUID:""",
    """(\\t|\\n|\s)Changes:(\\t|\\n|\s)*({policy}.+?)(\\t|\\n|")""",
  ]
  DupFields = [ "host->dest_host" ]
}
```