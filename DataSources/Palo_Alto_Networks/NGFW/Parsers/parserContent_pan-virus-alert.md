#### Parser Content
```Java
{
Name = pan-virus-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,virus,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"host":\{.*?"name":"({host}[^"]+)".*?\}""",
    """({host}[\w\-\.]+)\s{1,100}\d{1,100}
```