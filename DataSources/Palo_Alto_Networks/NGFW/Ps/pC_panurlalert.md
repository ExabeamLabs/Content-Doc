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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000}
```