#### Parser Content
```Java
{
Name = raw-674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-674"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Renewed:", "Ticket Options:" ] 
  Fields = [ 
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{4})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100

}
```