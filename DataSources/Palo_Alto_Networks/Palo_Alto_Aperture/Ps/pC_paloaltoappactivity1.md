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
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """activity_monitoring,"?({app}[^,"]{1,2000})""",
    """activity_monitoring,"{0,20}([^,]{0,2000},){5}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """,activity_monitoring,([^,]{0,2000},){4}"{0,20}([\w\s]{1,2000}|({user_email}[^@]{1,2000}@[^",]{1,2000}))"{0,20},({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?"""
   ]
}
```