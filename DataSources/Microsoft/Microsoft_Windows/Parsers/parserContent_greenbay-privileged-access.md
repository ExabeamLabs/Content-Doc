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
    """"subject-AccountName":"({user}[^"]{1,2000})""",
    """"level":"({outcome}[^"]{1,2000})""",
    """"time":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d\d:\d\d (am|AM|pm|PM))""",
    """"privileges":\[({privileges}.+?)\]""",
    """"subject-LogonID":"({logon_id}[^"]{1,2000})""",
    """"subject-AccountDomain":"({domain}[^"]{1,2000})""",
    """"subject-SecurityID":"({user_sid}[^"]{1,2000})""",
    """"event_id":"({event_code}\d{1,100})""",
    """"computer":"({host}[^"]{1,2000})""",
  ]
  DupFields = [ "host->dest_host" ]
}
```