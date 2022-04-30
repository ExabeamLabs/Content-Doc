#### Parser Content
```Java
{
Name = raw-4649
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "account-deleted"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=4649""", """Message=A replay attack was detected.""", """SourceName =Microsoft Windows security auditing""", """TaskCategory=Other Logon/Logoff Events""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM))""",
    """EventCode=({event_code}\d{1,100})""",
    """ComputerName =({host}[^\s]{1,2000})""",
    """Keywords=({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """Message=({event_name}[^:]{1,2000}?)\s{1,100}\w+:""",
    """Subject:\s{1,100}Security ID:\s{1,100}({user_sid}[^:]{1,2000}?)\s{1,100}Account Name:""",
    """Subject:.+?Account Name:\s{1,100}({user}[^\s]{1,2000})""",
    """Subject:.+?Account Domain:\s{1,100}({domain}[^:]{1,2000}?)\s{1,100}Logon ID:""",
    """Subject:.+?Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Process ID:\s{1,100}({process_id}[^\s]{1,2000})""",
    """Process Name:\s{1,100}({process}(({directory}[^\s]{1,2000}?)\\{1,20})?({process_name}[^\s\\]{1,2000}))\s{1,100}Network Information:""",
    """Logon Process:\s{1,100}({auth_process}[^\s]{1,2000})""",
    """Authentication Package:\s{1,100}({auth_package}[^\s]{1,2000})""",
    """({additional_info}This event indicates that[^$]{1,2000}?)\s{0,100}$"""
  ]
  DupFields = [ "event_name->alert_name", "auth_process->alert_type" ]


}
```