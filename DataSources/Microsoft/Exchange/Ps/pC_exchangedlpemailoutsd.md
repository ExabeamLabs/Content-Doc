#### Parser Content
```Java
{
Name = exchange-dlp-email-out-sd
  Vendor = Microsoft
  Product = Exchange
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,STOREDRIVER,RECEIVE,""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)Z,(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100}
```