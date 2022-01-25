#### Parser Content
```Java
{
Name = raw-673
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-673"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Ticket Request:", "Ticket Options:" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({event_code}673)""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)\s{0,100}
```