#### Parser Content
```Java
{
Name = s-mimecast-app-activity
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ Application:""", """|auditType=""", """Action Performed - """, """|mcType=auditLog|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_index=({app}[^\s\|]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-].+?)\|""",
    """\|user=<?({user}[^<>]+?)>?\|""",
    """\|user=(|({user_email}[^@\|]+@({email_domain}[^@\|]+)))\|""",
    """\sApplication:\s*({additional_info}[^"]*)("|\s*$)""",
    """Action Performed - ({activity}.+?)(\s*:\s*|\s\w+:)""",
    """\sIP:\s*({src_ip}[a-fA-F\d\.:]+)"""
  ]
}
```