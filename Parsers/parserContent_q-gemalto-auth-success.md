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
    """""<\d+>\w+\s+\d+:\d+:\d+\s+({host}\S+)""",
    """At\s+({time}\d+/\d+/\d\d\d\d \d+:\d+:\d+ (am|AM|PM|pm)),\s*({user}[^\s\(]+)\S*\s+from\s+({src_ip}[a-fA-F\d.:]+)\s+did\s+({action}\S+)""",
    """using\s+({auth_method}\S+)""",
    """resulting in ({outcome}AUTH_SUCCESS)""",
  ]
}
```