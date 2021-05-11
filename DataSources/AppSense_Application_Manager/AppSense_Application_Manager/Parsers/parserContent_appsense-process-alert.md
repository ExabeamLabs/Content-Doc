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
      """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """ComputerName=({dest_host}[^\s]+)""",
      """Sid=({sid_user}[^\s]+)""",
      """\s{1,100}Type=({alert_severity}[^\s]+)""",
      """\'\w+:\\+(?i)users\\+({user}[^\\]+)""",
      """Hash:({md5}[^\s\]]+)""",
      """Vendor:\s{1,100}({process_vendor}[^\]]+)""",
      """Message=AppSense Application Manager ({alert_name}.+?)\s{1,100}(of [^\w]|\'|for)""",
      """Message=(The file )?\'.+?\'( has had)?\s{1,100}({alert_name}.+?)\s{0,100}(\.|of|for)""",
      """Message=\'(({domain}[^\\]+)\\+)?({user}[^']+)\'""",
      """\'({process}({directory}(?:(\w+:)*([\\\/]+[^\\\/'\]"]+)+)?[\\\/]+)({process_name}[^\\\/"\]]*?))(\s{1,100}\[\w+:|')""",
    ]
        DupFields=["process->path",
		   "dest_host->host",
		   "alert_name->alert_type",
		   "sid_user->account_id",
                   "directory->process_directory" ]
  }
```