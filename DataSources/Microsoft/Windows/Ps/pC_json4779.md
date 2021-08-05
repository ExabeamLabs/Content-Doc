#### Parser Content
```Java
{
Name = json-4779
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-4779"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""""EventID":4779""", """A session was disconnected from a Window Station""", """Session Name"""]
  Fields = [
    """"EventTime":\s{0,100}"\s{0,100}({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """({event_name}A session was disconnected from a Window Station)""",
    """"(?i)HostName":"({host}[^"]{1,2000})"""",
    """({event_code}4779)""",
    """"AccountName":"({user}[^"]{1,2000})"""",
    """"AccountDomain":"({domain}[^"]{1,2000})"""",
    """"LogonID":"({logon_id}[^"]{1,2000})"""",
    """"SeverityValue":({severity}[^,]{1,2000})""", 
    """"ClientName":"({dest_host}[^"]{1,2000})"""",
    """"ClientAddress":"({dest_ip}[^"]{1,2000})"""",

  ]
}
```