#### Parser Content
```Java
{
Name = xml-4779
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4779"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4779<""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """<Computer>({host}[\w\-.]+)""",
    """({event_code}4779)""",
    """<Message>({event_name}[^.???]+)""",
    """<EventRecordID>({record_id}[^<]+)""",
    """'AccountName'>({user}[^"\s<]+)<""",
    """'AccountDomain'>({domain}[^"\s<]+)<""",
    """'LogonID'>({logon_id}[^"\s<]+)<""",
    """'ClientName'>({src_host}[\w\-.]+)<""",
    """'ClientAddress'>({src_ip}[A-Fa-f:\d.]+)<""",
    """<Keywords>({outcome}[^<]+)</Keywords>"""
  ]
}
```