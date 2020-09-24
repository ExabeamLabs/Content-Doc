#### Parser Content
```Java
{
Name = onespan-failed-logon
  Vendor = OneSpan
  Product = OneSpan
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS z"
  Conditions = [ """{Input Details:""", """{User ID""",  """User authentication failed""", """ ikeyserver""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+ikeyserver""",
    """time\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+)""",
    """\{Source Location:({src_ip}[a-fA-F\d\.:]+)""",
    """\{Client Location:({dest_ip}[a-fA-F\d\.:]+)""",
    """\{Input Details:\s*\{User ID\s*:\s*({user}[^\}]+)""",
    """\{Client Type:({logon_type}[^\}]+)""",
    """\{Status Message\s*:\s*({event_name}[^\}]+)""",
    """({outcome}Failure)""",
    """\{Input Details:.+?\{Domain Name\s*:\s*({domain}[^\}]+)""",
    """\{Reason\s*:\s*({failure_reason}[^\}]+)""",
  ]
}
```