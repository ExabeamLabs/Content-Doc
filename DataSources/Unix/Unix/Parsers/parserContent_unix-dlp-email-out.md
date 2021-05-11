#### Parser Content
```Java
{
Name = unix-dlp-email-out
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ sSMTP[""", """]: Sent mail""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Sent mail for ({sender}[^\s]+)""",
    """outbytes=({bytes}\d{1,100})""",
    """uid=({email_id}[^\s]+)""",
    """username=({user}[^\s]+)"""
  ]
}
```