#### Parser Content
```Java
{
Name = q-gemalto-auth-success
  Vendor = Gemalto
  Product = Gemalto MFA
  Lms = QRadar
  DataType = "authentication-successful"
  TimeFormat = "MM/d/yyyy H:mm:ss a"
  Conditions = [ """ resulting in AUTH_SUCCESS. """ ]
  Fields = [
    """""<\d{1,100}>\w+\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}({host}\S+)""",
    """At\s{1,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|PM|pm)),\s{0,100}({user}[^\s\(]{1,2000})\S*\s{1,100}from\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}did\s{1,100}({action}\S+)""",
    """using\s{1,100}({auth_method}\S+)""",
    """resulting in ({outcome}AUTH_SUCCESS)""",
  ]
}
```