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
    """\d{1,100}:\d{1,100}\.\d{1,100}Z,[A-Fa-f:\d.]+,({host}[\w\.\-]+),""",
    """({additional_info}SMTP),({action}[^,]+),({alert_id}\d{1,100}),""",
    """({direction}Incoming)""",
    """,({recipients}({recipient}[^\s@;,"]+@({external_domain}[^\s@;,"]+))[^,]*?),(?:[^",]+?,|,)({bytes}\d{1,100}),({num_recipients}\d{1,100}),(?:"(?:[^"]|"")+",|[^",]+?,|,){6}Incoming,""",
    """,\s{0,100}({subject}[^,]*?)\s{0,100}
```