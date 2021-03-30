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
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """({time}\d+\/\d+\/\d+ \d+:\d+:\d+ (am|AM|pm|PM) \w+),(?:|({src_host}[^,]+)),(?:|({alert_name}[^,]+)),(?:|({outcome}[^,]+)),[^,]*,McAfee Endpoint Security,([^,]*,){2}(?:|({alert_type}[^,]+)),(?:|({additional_info}[^,]+)),(?:|({alert_severity}[^,]+)),(?:|({process}[^,]*?({process_name}[^,\\\/]+))),([^,]*,){2}\s*(?:,|({malware_url}.+?))\s*$""",
    ]
  }
```