#### Parser Content
```Java
{
Name = exchange-dlp-email-in-2
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:m:ss.SSS"
  Conditions = [ """,SMTP,SEND,""", """,Incoming,""" ]
  Fields = [
    """,({time}\d\d\d\d-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100})""",
    """\d{1,100}:\d{1,100}\.\d{1,100}Z,[A-Fa-f:\d.]{1,2000}
```