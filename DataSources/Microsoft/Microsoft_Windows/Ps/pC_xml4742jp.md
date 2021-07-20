#### Parser Content
```Java
{
Name = xml-4742-jp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4742<""", """コンピューター アカウントが変更されました。""" ]
  Fields = [
    """({event_name}コンピューター アカウントが変更されました。)""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """({event_code}4742)""",
    """<EventRecordID>({record_id}[^<]{1,2000})""",
    """'SubjectUserSid'>({user_sid}[^"\s<]{1,2000})<""",
    """'SubjectUserName'>({user}[^"\s<]{1,2000})<""",
    """'SubjectDomainName'>({domain}[^"\s<]{1,2000})<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]{1,2000})<""",
  ]
  DupFields = [ "host->dest_host"]
}
```