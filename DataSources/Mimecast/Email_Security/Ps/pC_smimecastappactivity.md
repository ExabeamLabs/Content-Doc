#### Parser Content
```Java
{
Name = s-mimecast-app-activity
  Vendor = Mimecast
  Product = Email Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ Application:""", """|auditType=""", """Action Performed - """, """|mcType=auditLog|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_index=({app}[^\s\|]{1,2000})""",
    """date=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-].+?)\|""",
    """\|user=<?({user}[^<>]{1,2000}?)>?\|""",
    """\|user=(|({user_email}[^@\|]{1,2000}@({email_domain}[^@\|]{1,2000})))\|""",
    """\sApplication:\s{0,100}({additional_info}[^"]{0,2000})("|\s{0,100}$)""",
    """Action Performed - ({activity}.+?)(\s{0,100}:\s{0,100}|\s\w+:)""",
    """\sIP:\s{0,100}({src_ip}[a-fA-F\d\.:]{1,2000})"""
  ]


}
```