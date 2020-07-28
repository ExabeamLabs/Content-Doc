#### Parser Content
```Java
{
Name = json-4779
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4779"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""""EventID":4779""", """A session was disconnected from a Window Station""", """Session Name"""]
  Fields = [
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """({event_name}A session was disconnected from a Window Station)""",
    """"HostName":"({host}[^"]+)"""",
    """({event_code}4779)""",
    """"AccountName":"({user}[^"]+)"""",
    """"AccountDomain":"({domain}[^"]+)"""",
    """"LogonID":"({logon_id}[^"]+)"""",
    """"SeverityValue":({severity}[^,]+)""", 
    """"ClientName":"({dest_host}[^"]+)"""",
    """"ClientAddress":"({dest_ip}[^"]+)"""",

  ]
}
```