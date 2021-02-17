#### Parser Content
```Java
{
Name = xml-4778
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4778"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4778<""" ]
  Fields = [
    """<TimeCreated SystemTime(\\)?='({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """<Computer>({host}[\w\-.]+)""",
    """({event_name}A session was reconnected to a Window Station)""",
    """({event_code}4778)""",
    """<EventRecordID>({record_id}[^<]+)""",
    """'AccountName'>({user}[^"\s<]+)<""",
    """'AccountDomain'>({domain}[^"\s<]+)<""",
    """'LogonID'>({logon_id}[^"\s<]+)<""",
    """'ClientName'>({src_host}[\w\-.]+)<""",
    """'ClientAddress'>({src_ip}[A-Fa-f:\d.]+)<""",
  ]
}
```