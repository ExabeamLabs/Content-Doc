#### Parser Content
```Java
{
Name = symantec-security-alert-3
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,Rule:""", """,Registry Read,Begin:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({alert_severity}[^,]{1,2000}),({alert_type}[^,]{1,2000}),({host}[^,]{1,2000}),({outcome}[^,]{1,2000}),[^,]{0,2000},({activity}[^,]{1,2000}),([^,]{0,2000},){2}({alert_name}[^,]{1,2000}),[^,]{0,2000},({file_path}({file_parent}[^,]{0,2000}?[\\\/]{1,2000})?({file_name}[^,\\\/]{1,2000}?(\.({file_ext}\w+))?)?),""",
    """,User:\s{0,100}(SYSTEM|({user}[^,]{1,2000})),""",
    """,Domain:\s{0,100}({domain}[^,]{1,2000}),""",
    """,File size \(bytes\):\s{0,100}(0|({bytes}\d{1,100})),""",
  ]
}
```