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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Sent mail for ({sender}[^\s]{1,2000})""",
    """outbytes=({bytes}\d{1,100})""",
    """uid=({email_id}[^\s]{1,2000})""",
    """username=({user}[^\s]{1,2000})"""
  ]
}
```