#### Parser Content
```Java
{
Name = s-mcafee-security-alert-1
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "M/d/yy h:mm:ss a zzz"
    Conditions = [ """,McAfee Endpoint Security,""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM) \w+),(?:|({src_host}[^,]{1,2000})),(?:|({alert_name}[^,]{1,2000})),(?:|({outcome}[^,]{1,2000})),[^,]{0,2000}
```