#### Parser Content
```Java
{
Name = windows-kinesis-firehose-4672
  DataType = "windows-privileged-access"
  Conditions = [ """"EventId":4672""", """Special privileges assigned to new logon""", """"MachineName":""", """"TimeCreated":""", """Privileges""" ]
  Fields = ${WinParserTemplates.windows-kinesis-firehose.Fields} [
    """({event_name}Special privileges assigned to new logon)""",
    """\scategoryOutcome=(|/({outcome}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """Type\s{0,100}=\s{0,100}"({outcome}[^";]{1,2000})"""",
    """Keywords=({outcome}[^=]{1,2000}?);?\s{0,100}(\w{1,100}=)""",
    """Account Name(:|=)\s{0,100}(-|SYSTEM|({user}[^\s]{1,2000}?))[\s;]{0,2000}Account Domain(:|=)""",
    """Account Domain(:|=)\s{0,100}(-|({domain}[^\s]{1,2000}?))[\s;]{0,2000}Logon ID(:|=)""",
    """\s{0,100}Logon ID(:|=)\s{0,100}({logon_id}[^=]{1,2000}?)[\s;]{0,2000}Privileges(:|=)\s{0,100}({privileges}[^=]{1,2000})\s{1,100}(\w{1,100}=)""",
    """sourceip="({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """EVENT_TYPE="({outcome}[^"]{1,2000})""""
  ]
  DupFields = ["host->dest_host"]
}
windows-kinesis-firehose = {
  Vendor = Microsoft
  Product = Windows
  Lms = Kinesis Firehose
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"EventId":({event_code}\d{1,5})"""
    """"MachineName":"({host}[^"]{1,2000})"""",
    """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
  ]

```