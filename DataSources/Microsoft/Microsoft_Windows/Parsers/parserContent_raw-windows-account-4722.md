#### Parser Content
```Java
{
Name = raw-windows-account-4722
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-enabled"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "A user account was enabled" ]
  Fields = [
    """({event_name}A user account was enabled)""",
     """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
     """"_raw":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
     """exabeam_source=({host}[A-Fa-f:\d.]+)""",
     """\s{1,100}(?i)(((audit|success)( |_)(success|audit))|information)\s{1,100}({host}[\w.\-]+)""",             
     """<Computer>({host}[^<]+)</Computer>""",
     """Computer(\w+)?["\s]*(:|=)\s{0,100}"?({host}.+?)("|\s)""",
     """"system_name":"({host}[^"]+)"""",
     """({event_code}4722)""",
     """Security(,|\srn=|\s{1,100})({record_id}\d{1,100})""",
     """Account Name:\s{0,100}\\?({user}[^\s]+)\s{0,100}Account Domain:\s{0,100}({domain}[^\s]+).+?Logon ID:\s{0,100}({logon_id}[^\s]+)\s{0,100}Target.+?Account Name:\s{0,100}({target_user}[^\s]+)\s{0,100}Account Domain:\s{0,100}({target_domain}[^\s"]+)""",
     """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
     """"TargetAccount":"(({target_domain}[^\\\s"]+)\\+)?({target_user}[^\\\s"]+)""",
     """"SubjectLogonId":"({logon_id}[^\s"]+)""",
  ]
}
```