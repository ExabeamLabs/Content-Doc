#### Parser Content
```Java
{
Name = s-mimecast-app-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ Application:""", """|action=""", """|auditType=""", """|mcType=auditLog|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """date=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-].+?)\|""",
    """\|user=(|({user}.+?))\|""",
    """\|user=(|({user_email}[^@\|]{1,2000}@({email_domain}[^@\|]{1,2000})))\|""",
    """\sApplication:\s{0,100}({app}[^,]{0,2000})(,|\s{0,100}$)""",
    """\|app=(|({app}.+?))\|""",
    """\sIP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})(,|\s{0,100}$)""",
    """\|src=(|({src_ip}[a-fA-F\d.:]{1,2000}))\|""",
    """\|action=(|({outcome}.+?))\|"""
  ]


}
```