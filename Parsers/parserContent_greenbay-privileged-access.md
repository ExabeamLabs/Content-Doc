#### Parser Content
```Java
{
Name = greenbay-privileged-access
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Special privileges assigned to new logon""", """"subject-AccountName":""", """"privileges":""" ]
  Fields = [
    """({event_name}Special privileges assigned to new logon)""",
    """"subject-AccountName":"({user}[^"]+)""",
    """"level":"({outcome}[^"]+)""",
    """"time":"({time}\d+\/\d+\/\d\d\d\d \d+:\d\d:\d\d (am|AM|pm|PM))""",
    """"privileges":\[({privileges}.+?)\]""",
    """"subject-LogonID":"({logon_id}[^"]+)""",
    """"subject-AccountDomain":"({domain}[^"]+)""",
    """"subject-SecurityID":"({user_sid}[^"]+)""",
    """"event_id":"({event_code}\d+)""",
    """"computer":"({host}[^"]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```