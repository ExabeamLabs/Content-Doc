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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"event_id"\s{0,100}:\s{0,100}({event_code}\d{1,100})""",
    """"(SubjectUserName)"\s{0,100}:\s{0,100}"({user}.+?)\s{0,100}"""",
    """"(SubjectDomainName)"\s{0,100}:\s{0,100}"({domain}.+?)\s{0,100}"""",
    """"(SubjectLogonId|logon_id)"\s{0,100}:\s{0,100}"({logon_id}.+?)\s{0,100}"""",
    """(\\t|\\n|\s)Category:(\\t|\\n|\s)*({audit_category}.+?)(\\t|\\n|\s)+Subcategory:""",
    """(\\t|\\n|\s)Subcategory:(\\t|\\n|\s)*({subcategory}.+?)(\\t|\\n|\s)+Subcategory GUID:""",
    """(\\t|\\n|\s)Changes:(\\t|\\n|\s)*({policy}.+?)(\\t|\\n|")""",
  ]
  DupFields = [ "host->dest_host" ]
}
```