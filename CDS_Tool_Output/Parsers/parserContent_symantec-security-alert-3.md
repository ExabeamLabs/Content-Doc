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
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({alert_severity}[^,]+),({alert_type}[^,]+),({host}[^,]+),({outcome}[^,]+),[^,]*,({activity}[^,]+),([^,]*,){2}({alert_name}[^,]+),[^,]*,({file_path}({file_parent}[^,]*?[\\\/]+)?({file_name}[^,\\\/]+?(\.({file_ext}\w+))?)?),""",
    """,User:\s*(SYSTEM|({user}[^,]+)),""",
    """,Domain:\s*({domain}[^,]+),""",
    """,File size \(bytes\):\s*(0|({bytes}\d+)),""",
  ]
}
```