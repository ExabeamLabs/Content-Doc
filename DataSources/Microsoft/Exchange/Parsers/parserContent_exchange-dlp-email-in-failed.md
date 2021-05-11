#### Parser Content
```Java
{
Name = exchange-dlp-email-in-failed
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Incoming,""", """,FAIL,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,[^,]*,({host}[^,]+),([^,]*,){5}FAIL,""",
    """,({host}[^\s,]+),([^,]*,){3}\w+,FAIL,""",
    """,[^\s,]+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),([^,]*,){3}\w+,FAIL,""",
    """,\s{0,100}(?:'|")?({host}[\w\.-]+)(?:'|")?\s{0,100}
```