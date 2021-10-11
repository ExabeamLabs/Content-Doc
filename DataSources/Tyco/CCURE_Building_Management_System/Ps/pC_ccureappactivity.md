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
              """exabeam_raw=[^,]{0,2000},({user}[^,]{1,2000})""",
              """exabeam_raw=([^,]{0,2000},){2}({object}.+?)\s{1,100}\('""",
              """exabeam_raw=.+?\('({additional_info}[^']{1,2000})""",
              """exabeam_host=({host}[^\s]{1,2000})""",
              """({time}\d\d\d\d\-\d\d\-\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|PM|pm))"""
	]
}
```