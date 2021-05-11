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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}ikeyserver""",
    """time\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d \w+)""",
    """\{Source Location:({src_ip}[a-fA-F\d\.:]+)""",
    """\{Client Location:({dest_ip}[a-fA-F\d\.:]+)""",
    """\{Input Details:\s{0,100}\{User ID\s{0,100}:\s{0,100}({user}[^\}]+)""",
    """\{Client Type:({logon_type}[^\}]+)""",
    """\{Status Message\s{0,100}:\s{0,100}({event_name}[^\}]+)""",
    """({outcome}Failure)""",
    """\{Input Details:.+?\{Domain Name\s{0,100}:\s{0,100}({domain}[^\}]+)""",
    """\{Reason\s{0,100}:\s{0,100}({failure_reason}[^\}]+)""",
  ]
}
```