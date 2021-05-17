#### Parser Content
```Java
{
Name = raw-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4771"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ "Kerberos pre-authentication failed" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """"event_time":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s(AM|PM))""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """exabeam_host=(::ffff:)?({host}[\w.-]{1,2000})""",
    """(?i)(((audit|failure)( |_)(audit|failure))|information)(,|s+)(::ffff:)?({host}[\w.-]{1,2000})(\s|,|"|$)""",
    """__li_source_path="{0,20}(::ffff:)?({host}[^"]{1,2000})"""",
    """(::ffff:)?({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing\s{0,100}\(""",
    """<?Computer>?(Name)?["\s:=]{0,2000}(::ffff:)?({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?(::ffff:)?({host}.+?)("|\s|;)""",
    """({event_code}4771)""",
    """Account Information(:|=)\s{0,100};*Security ID(:|=)\s{0,100}({user_sid}.+?)\s{0,100};*Account""",
    """Account Name(:|=)\s{0,100}({user}.+?)\s{0,100};*Service Information""",
    """Service Name(:|=)\s{0,100}\w+\/(?=\w)({domain}.+?)\s{0,100};*Network Information""",
    """Client Address(:|=)\s{0,100}(::[\w]{1,2000}:)?({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """Failure Code(:|=)\s{0,100}({result_code}[\w]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```