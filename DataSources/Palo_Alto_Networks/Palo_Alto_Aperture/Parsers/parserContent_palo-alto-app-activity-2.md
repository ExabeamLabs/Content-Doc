#### Parser Content
```Java
{
Name = palo-alto-app-activity-2
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ Aperture """, """,admin_audit,""","""create""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s({host}[^\s]+)""",
    """admin_audit,"*({user_email}[^@]+[^,"]+)"*,"""
    """admin_audit,"*([^,]*,){2}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"*,""",
    """admin_audit,"*([^,]*,){7}"*({action}[^,"]+)"*,"""
  ]
}
```