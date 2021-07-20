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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\s({bucket}\S+)\s\[\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d""",
    """\[({time}\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """\d\d\d\d:\d\d:\d\d:\d\d\s\+\d\d\d\d\]\s({src_ip}[^\s]{1,2000})""",
    """:assumed-role\/({accesses}[^\/]{1,2000}\/({user}[^\/\s]{1,2000}))""",
    """assumed-role\/({user}[^\/]{1,2000})"""
    """\s(REST|BATCH)\.({method}\w+)""",
    """\s(REST|BATCH)\.\w+\.\w+\s(({file_path}({file_parent}[^\s]{0,2000})\/({file_name}[^\s\/]{1,2000})))\s""",
    """\s(REST|BATCH)\.\w+\.\w+\s\S+\s"[^"]{1,2000}"\s({outcome}\d{1,100})""",
    """\s(REST|BATCH)\.\w+\.\w+\s(-|[^\s]{1,2000})\s"[^"]{1,2000}"\s({outcome}[^\s]{1,2000})\s(-|({failure_reason}[^\s]{1,2000}))\s(-|({bytes_out}[^\s]{1,2000}))\s(-|[^\s]{1,2000})\s(-|[^\s]{1,2000})\s(-|[^\s]{1,2000})\s"(-|[^\s]{1,2000})"\s"(-|({user_agent}[^"]{1,2000}))"\s"""
    """({service}s3.amazonaws.com)""",
    """\s({activity}(REST|BATCH)\.\w+\.\w+)""",
  ]
  DupFields = [ "accesses->role", "file_path->object" ]
}
```