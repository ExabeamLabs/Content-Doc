#### Parser Content
```Java
{
Name = palo-alto-dlp-alert-1
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ Aperture """, """,policy_violation,""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s({host}[^\s]+)""",
    """,policy_violation,"*({app}[^,"]+)"*,""",
    """,policy_violation,"*([^,]*,){1}({alert_severity}\d+(\.\d)?)"""
    """,policy_violation,"*([^,]*,){2}({alert_id}[^,]+)"*,"""
    """,policy_violation,"*([^,]*,){4}"*({user_email}[^@]+@[^,"]+)"*,([^,]*,){3}"*({additional_info}[^",]+)\s*"*,""",
    """({alert_name}policy_violation)"""
  ]
  DupFields = ["alert_name->alert_type"]
}
```