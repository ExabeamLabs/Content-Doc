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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({host}[\w\-\.]{1,2000})[\s\-]{1,2000}\d{1,100

}
```