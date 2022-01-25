#### Parser Content
```Java
{
Name = palo-alto-app-login-1
  Vendor = Palo Alto Networks
  Product = Palo Alto Aperture
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ Aperture """, """,admin_audit,""","""sign_in""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """admin_audit,"{0,20}({user_email}[^@]{1,2000}[^,"]{1,2000})"{0,20}
```