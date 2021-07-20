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
      """({host}[\w\-\.]{1,2000})\s{1,100}ldap-access:""",
      """ldap-access:\s{0,100}\[({time}\d{1,100}\/\w+\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100} (\-|\+)\d{1,100})""",
      """\Wuid=({user}[^\s,]{1,2000})""",
      """\sconnection from\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100})\s{1,100}to\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sBIND .*?\sRESULT err=({outcome}\d{1,100})"""
    ]
  }
```