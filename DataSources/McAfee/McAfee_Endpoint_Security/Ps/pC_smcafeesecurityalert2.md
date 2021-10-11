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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM) \w+),(?:|({src_host}[^,]{1,2000})),(?:|({alert_name}[^,]{1,2000})),(?:|({outcome}[^,]{1,2000})),[^,]{0,2000},Endpoint Security Platform,([^,]{0,2000},){2}(?:|({alert_type}[^,]{1,2000})),(?:|({additional_info}[^,]{1,2000})),(?:|({alert_severity}[^,]{1,2000})),(?:|({process}[^,]{0,2000}?({process_name}[^,\\\/]{1,2000}))),([^,]{0,2000},){2}\s{0,100}(?:,|({malware_url}.+?))\s{0,100}$""",
  ]
}
```