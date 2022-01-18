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
    """<TimeCreated SystemTime(\\)?='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """({event_code}4779)""",
    """<Message>({event_name}[^.。]{1,2000})""",
    """<EventRecordID>({record_id}[^<]{1,2000})""",
    """'AccountName'>({user}[^"\s<]{1,2000})<""",
    """'AccountDomain'>({domain}[^"\s<]{1,2000})<""",
    """'LogonID'>({logon_id}[^"\s<]{1,2000})<""",
    """'ClientName'>({src_host}[\w\-.]{1,2000})<""",
    """'ClientAddress'>({src_ip}[A-Fa-f:\d.]{1,2000})<""",
    """<Keywords>({outcome}[^<]{1,2000})</Keywords>"""
  ]


}
```