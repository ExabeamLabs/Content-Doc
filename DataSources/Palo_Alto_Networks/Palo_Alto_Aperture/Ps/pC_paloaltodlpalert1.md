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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """,policy_violation,"{0,20}({app}[^,"]{1,2000})"{0,20},""",
    """,policy_violation,"{0,20}([^,]{0,2000},){1}({alert_severity}\d{1,100}(\.\d)?)"""
    """,policy_violation,"{0,20}([^,]{0,2000},){2}({alert_id}[^,]{1,2000})"{0,20},"""
    """,policy_violation,"{0,20}([^,]{0,2000},){4}"{0,20}({user_email}[^@]{1,2000}@[^,"]{1,2000})"{0,20},([^,]{0,2000},){3}"{0,20}({additional_info}[^",]{1,2000})\s{0,100}"{0,20},""",
    """({alert_name}policy_violation)"""
  ]
  DupFields = ["alert_name->alert_type"]
}
```