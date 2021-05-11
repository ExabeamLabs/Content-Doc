#### Parser Content
```Java
{
Name = exchange-dlp-email-out-failed
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,Originating,""", """,FAIL,""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,[^,]*,({host}[^,]+),([^,]*,){5}FAIL,""",
    """({additional_info}\w+,FAIL),""",
    """({action}FAIL)""",
    """,FAIL,\s{0,100}({alert_id}\d{1,100})""",
    """,\s{0,100}(?:'|")?([^,]+Recipients_cn\=)?({recipients}({recipient}[^,;'"\s@]+@({external_domain}[^,;'"\s@]+))[^,]*?)\s{0,100}(?:'|")?,([^,]*,){9}Originating,""",
    """,\s{0,100}(({bytes}\d{1,100})|)\s{0,100}
```