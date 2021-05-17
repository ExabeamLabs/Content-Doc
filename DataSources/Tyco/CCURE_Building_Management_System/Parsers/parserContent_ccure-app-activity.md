#### Parser Content
```Java
{
Name = ccure-app-activity
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss a"
  Conditions = [ """<CCure App Activity Conditions>""" ]
  Fields = [
              """exabeam_raw=({activity}[^,]{1,2000})""",
              """exabeam_raw=[^,]{0,2000}
```