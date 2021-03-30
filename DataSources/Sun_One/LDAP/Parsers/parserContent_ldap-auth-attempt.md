#### Parser Content
```Java
{
Name = ldap-auth-attempt
    Vendor = Sun One
    Product = LDAP
    Lms = Direct
    DataType = "authentication-attempt"
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """ldap-access:""", """ BIND """ ]
    Fields = [
      """({host}[\w\-\.]+)\s+ldap-access:""",
      """ldap-access:\s*\[({time}\d+\/\w+\/\d+:\d+:\d+:\d+ (\-|\+)\d+)""",
      """\Wuid=({user}[^\s,]+)""",
      """\sconnection from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d+)\s+to\s+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sBIND .*?\sRESULT err=({outcome}\d+)"""
    ]
  }
```