#### Parser Content
```Java
{
Name = s-mcafee-security-alert-2
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/d/yy h:mm:ss a zzz"
  Conditions = [ """,Endpoint Security Platform,""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM) \w+),(?:|({src_host}[^,]+)),(?:|({alert_name}[^,]+)),(?:|({outcome}[^,]+)),[^,]*,Endpoint Security Platform,([^,]*,){2}(?:|({alert_type}[^,]+)),(?:|({additional_info}[^,]+)),(?:|({alert_severity}[^,]+)),(?:|({process}[^,]*?({process_name}[^,\\\/]+))),([^,]*,){2}\s{0,100}(?:,|({malware_url}.+?))\s{0,100}$""",
  ]
}
```