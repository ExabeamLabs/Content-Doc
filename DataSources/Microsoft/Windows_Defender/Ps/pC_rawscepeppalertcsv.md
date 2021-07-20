#### Parser Content
```Java
{
Name = raw-scep-epp-alert-csv
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mma"
  Conditions = [ ",SystemCenterEndpointProtection" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """({time}\w+\s{1,100}\d{1,100}\s{1,100}\d\d\d\d\s{1,100}\d{1,2}:\d\d(AM|am|PM|pm))\,({alert_id}[^\,]{1,2000})\,({alert_name}[^\,]{1,2000})\,\w+\,({src_host}[^\,]{1,2000})\,[^,]{1,2000}\,({additional_info}[^\,]{1,2000})\,(?:NA|({domain}[^\\]{1,2000}))\\({user}[^\,]{1,2000})\,({alert_type}[^\,]{1,2000})\,({alert_severity}[^\,]{1,2000})\,SystemCenterEndpointProtection"""
  ]
}
```