#### Parser Content
```Java
{
Name = symantec-email-alert-out
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """protocol=SMTP""","""incident_id=""", """sender=""", """recipient=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s{1,100}incident_id=""",
    """recipient=({recipient}[^,@]+@({external_domain}[^,]+)),""",
    """sender=({sender}[^,]+),""",
    """Subject=({subject}.+?)\s{0,100}
```