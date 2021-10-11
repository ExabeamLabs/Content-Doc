#### Parser Content
```Java
{
Name = paloalto-web-activity
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,url,""", """web-browsing,"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000}
```