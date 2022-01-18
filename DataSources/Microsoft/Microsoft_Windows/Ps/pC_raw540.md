#### Parser Content
```Java
{
Name = raw-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-540"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Logon Type:", "Successful Network Logon:" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """\s(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})\s{1,100}540\s{1,100}Security""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(?i)(((audit|success)( |_)(success|audit))|information)\s{0,100

}
```