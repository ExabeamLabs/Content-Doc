#### Parser Content
```Java
{
Name = appsense-process-alert
    Vendor = AppSense Application Manager
  Product = AppSense Application Manager
    Lms = Splunk
    DataType = "process-alert"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ """AppSense Application Manager""", """SourceName=""", """Message=""", """EventCode=""" ]
    Fields = [
      """({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """ComputerName=({dest_host}[^\s]+)""",
      """Sid=({sid_user}[^\s]+)""",
      """\s+Type=({alert_severity}[^\s]+)""",
      """\'\w+:\\+(?i)users\\+({user}[^\\]+)""",
      """Hash:({md5}[^\s\]]+)""",
      """Vendor:\s+({process_vendor}[^\]]+)""",
      """Message=AppSense Application Manager ({alert_name}.+?)\s+(of [^\w]|\'|for)""",
      """Message=(The file )?\'.+?\'( has had)?\s+({alert_name}.+?)\s*(\.|of|for)""",
      """Message=\'(({domain}[^\\]+)\\+)?({user}[^']+)\'""",
      """\'({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/'\]"]+)+)?[\\\/]+)({process_name}[^\\\/"\]]*?))(\s+\[\w+:|')""",
    ]
        DupFields=["process->path",
		   "dest_host->host",
		   "alert_name->alert_type",
		   "sid_user->account_id",
                   "directory->process_directory" ]
  }
```