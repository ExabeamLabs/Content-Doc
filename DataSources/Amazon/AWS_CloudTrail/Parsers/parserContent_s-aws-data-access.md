#### Parser Content
```Java
{
Name = s-aws-data-access
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "cloud-storage-access"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss"
  Conditions = ["""requestClientApplication=AWS Collector""", """|SkyFormation Cloud Apps Security|""", """ arn:aws""" , """.amazonaws.com """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\s({bucket}\S+)\s\[\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d""",
    """\[({time}\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """\d\d\d\d:\d\d:\d\d:\d\d\s\+\d\d\d\d\]\s({src_ip}[^\s]+)""",
    """:assumed-role\/({accesses}[^\/]+\/({user}[^\/\s]+))""",
    """assumed-role\/({user}[^\/]+)"""
    """\s(REST|BATCH)\.({method}\w+)""",
    """\s(REST|BATCH)\.\w+\.\w+\s(({file_path}({file_parent}[^\s]*)\/({file_name}[^\s\/]+)))\s""",
    """\s(REST|BATCH)\.\w+\.\w+\s\S+\s"[^"]+"\s({outcome}\d{1,100})""",
    """\s(REST|BATCH)\.\w+\.\w+\s(-|[^\s]+)\s"[^"]+"\s({outcome}[^\s]+)\s(-|({failure_reason}[^\s]+))\s(-|({bytes_out}[^\s]+))\s(-|[^\s]+)\s(-|[^\s]+)\s(-|[^\s]+)\s"(-|[^\s]+)"\s"(-|({user_agent}[^"]+))"\s"""
    """({service}s3.amazonaws.com)""",
    """\s({activity}(REST|BATCH)\.\w+\.\w+)""",
  ]
  DupFields = [ "accesses->role", "file_path->object" ]
}
```