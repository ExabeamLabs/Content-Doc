#### Parser Content
```Java
{
Name = avecto-local-logon
    Vendor = Avecto
    Product = Avecto Defendpoint
    Lms = Splunk
    DataType = "local-logon"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """SourceName=Avecto Defendpoint Service""", """Message=Detected user logon"""]
    Fields = [
      """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[^\s]+)""",
      """Message=({activity_type}.+?)\s+Command Line:""",
      """User Name:\s*(?:[A-F\d\-]{36}|({user}.+?))\s+User Domain SID:""",
      """User Domain Name:\s*({domain}.*?)\s+User Domain Name""",
      """User SID:\s*({user_sid}.*?)\s+User Name""",
      """Administrator:\s*({admin}.*?)\s+Power User""",
      """Power User:\s*({power_user}.*?)\s+Workstyle""",
      """Workstyle:\s*({account_info}.*?)\s+Workstyle""",
      """IP4 Addresses:\s*[^,]+,({src_ip}.+?)(,|$|\s)""",
    ]
  DupFields = [ "host->dest_host" ]
  }
```