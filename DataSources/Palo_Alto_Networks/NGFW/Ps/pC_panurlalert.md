#### Parser Content
```Java
{
Name = pan-url-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,url,""",""",malware,""" ]
  Fields = [
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}\d{1,100}
```