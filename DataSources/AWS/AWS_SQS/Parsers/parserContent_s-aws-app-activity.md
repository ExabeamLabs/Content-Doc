#### Parser Content
```Java
{
Name = s-aws-app-activity
  Vendor = AWS
  Product = AWS SQS
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = ["""=AWS Collector""", """|SkyFormation Cloud Apps Security|""", "|audit-event|" ]
  Fields = [
    """\s({host}\S+)\s\[\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d""",
    """\[({time}\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """\d\d\d\d:\d\d:\d\d:\d\d\s\+\d\d\d\d\]\s({src_ip}[^\s]+)""",
    """:assumed-role\/({accesses}[^\/]+\/({user}[^\/\s]+))""",
    """\s(REST|BATCH)\.({method}\w+)""",
    """\s(REST|BATCH)\.\w+\.\w+\s(({file_path}({file_parent}[^\s]*)\/({file_name}[^\s\/]+)))\s""",
    """\s(REST|BATCH)\.\w+\.\w+\s\S+\s"[^"]+"\s({outcome}\d+)""",
    """({app}AWS)""",
    """\s({activity}(REST|BATCH)\.\w+\.\w+)""",
  ]
  DupFields = [ "accesses->role", "file_path->object" ]
}
```