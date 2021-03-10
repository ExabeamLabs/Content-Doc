#### Parser Content
```Java
{
Name = raw-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Kerberos pre-authentication failed" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """"event_time":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.-]+)""",
    """(?i)(((audit|failure)( |_)(audit|failure))|information)(,|s+)({host}[\w.-]+)(\s|,|"|$)""",
    """__li_source_path="*({host}[^"]+)"""",
    """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing\s*\(""",
    """<?Computer>?(Name)?["\s:=]*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s|;)""",
    """({event_code}4771)""",
    """Account Information:\s*Security ID:\s*({user_sid}.+?)\s*Account""",
    """Account Name:\s*({user}.+?)\s*Service Information""",
    """Service Name:\s*\w+\/(?=\w)({domain}.+?)\s*Network Information""",
    """Client Address:\s*(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)""",
    """Failure Code:\s*({result_code}[\w]+)"""
  ]
}
```