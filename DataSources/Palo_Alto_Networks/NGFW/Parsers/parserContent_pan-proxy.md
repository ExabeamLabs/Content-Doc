#### Parser Content
```Java
{
Name = pan-proxy
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,url,""", """(9999)"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({host}[\w\-\.]+)[\s\-]+\d{1,100}
```