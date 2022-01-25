#### Parser Content
```Java
{
Name = pan-data-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,data,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,({alert_type}[^,]{1,2000}),[^,]{0,2000}
```