#### Parser Content
```Java
{
Name = ccure-app-activity
  Vendor = CCURE
  Product = CCURE
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss a"
  Conditions = [ """<CCure App Activity Conditions>""" ]
  Fields = [
              """exabeam_raw=({activity}[^,]+)""",
              """exabeam_raw=[^,]*,({user}[^,]+)""",
              """exabeam_raw=([^,]*,){2}({object}.+?)\s+\('""",
              """exabeam_raw=.+?\('({additional_info}[^']+)""",
              """exabeam_host=({host}[^\s]+)""",
              """({time}\d\d\d\d\-\d\d\-\d\d \d+:\d+:\d+ (am|AM|PM|pm))"""
	]
}
```