#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-4
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  Conditions = [ """|symcdlpsys|""","""|POLICY|""", """|MONITOR_NAME|""", """|APPLICATION_NAME|""" ]
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Fields = [
    """OCCURRED_ON\|({time}\w+\s{1,100}\d{1,2}
```