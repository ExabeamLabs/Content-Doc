#### Parser Content
```Java
{
Name = gravityzone-security-alert-new-login
  Product = Bitdefender
  Vendor = Bitdefender GravityZone
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """gravityzone:""", """"name":"Login from new device"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"created":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({app}gravityzone)""",
    """"name":"({activity}[^"]{1,2000})""",
    """"user_name":"(({user_email}({user}[^"@\\\/\s]{1,2000})@({domain}[^.]{1,2000})[^"]{1,2000}))""",
    """"os":"({os}[^"]{1,2000})""",
    """"browser_name":"({browser}[^"]{1,2000})""",
    """"device_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
  DupFields = ["domain->email_domain"]
}
```