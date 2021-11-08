#### Parser Content
```Java
{
Name = cef-vontu-dlp-alert-2
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    Conditions = [ """Symantec|DLP""","""POLICY=""" ]
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """OCCURRED_ON=({time}\w+\s{1,100}\d{1,100}
```