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
      """ComputerName=({dest_host}[^\s]{1,2000})""",
      """Sid=({sid_user}[^\s]{1,2000})""",
      """\s{1,100}Type=({alert_severity}[^\s]{1,2000})""",
      """\'\w+:\\+(?i)users\\+({user}[^\\]{1,2000})""",
      """Hash:({md5}[^\s\]]{1,2000})""",
      """Vendor:\s{1,100}({process_vendor}[^\]]{1,2000})""",
      """Message=AppSense Application Manager ({alert_name}.+?)\s{1,100}(of [^\w]|\'|for)""",
      """Message=(The file )?\'.+?\'( has had)?\s{1,100}({alert_name}.+?)\s{0,100}(\.|of|for)""",
      """Message=\'(({domain}[^\\]{1,2000})\\+)?({user}[^']{1,2000})\'""",
      """\'({process}({directory}(?:(\w+:)*([\\\/]{1,2000}[^\\\/'\]"]{1,2000})+)?[\\\/]{1,2000})({process_name}[^\\\/"\]]{0,2000}?))(\s{1,100}\[\w+:|')""",
    ]
        DupFields=["process->path",
		   "dest_host->host",
		   "alert_name->alert_type",
		   "sid_user->account_id",
                   "directory->process_directory" ]
  }
```