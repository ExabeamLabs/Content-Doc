#### Parser Content
```Java
{
Name = palo-alto-app-activity-1
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""activity_monitoring""",""" Aperture """]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]+)""",
    """activity_monitoring,"?({app}[^,"]+)""",
    """activity_monitoring,"{0,20}([^,]*,){5}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,activity_monitoring,([^,]*,){4}"{0,20}([\w\s]+|({user_email}[^@]+@[^",]+))"{0,20}
```