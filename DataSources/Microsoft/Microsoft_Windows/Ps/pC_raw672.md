#### Parser Content
```Java
{
Name = raw-672
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-672"
  TimeFormat ="MMM dd HH:mm:ss yyyy"
  Conditions = [ "Service Name:", "Supplied Realm Name:", "krbtgt" ]
  Fields = [
    """({event_name}Account Logon)""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(\s{1,100}|\s{0,100

}
```