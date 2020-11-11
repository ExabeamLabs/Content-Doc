#### Parser Content
```Java
{
Name = quest-change-audit-file-open
        DataType = "file-operations"
        Conditions = [ """ opened"""", """"action": "Other"""", """"folderPath": """", """"timeDetected": """" ]
}

{
  Name = s-mimecast-app-login
  Vendor = Mimecast
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ Application:""", """|action=""", """|auditType=""", """|mcType=auditLog|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """date=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-].+?)\|""",
    """\|user=(|({user}.+?))\|""",
    """\|user=(|({user_email}[^@\|]+@[^@\|]+))\|""",
    """\sApplication:\s*({app}[^,]*)(,|\s*$)""",
    """\|app=(|({app}.+?))\|""",
    """\sIP:\s*({src_ip}[a-fA-F\d.:]+)(,|\s*$)""",
    """\|src=(|({src_ip}[a-fA-F\d.:]+))\|""",
    """\|action=(|({outcome}.+?))\|"""
  ]
}
```