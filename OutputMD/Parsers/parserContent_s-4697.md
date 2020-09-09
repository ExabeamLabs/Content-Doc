#### Parser Content
```Java
{
Name = s-4697
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """4697""", """A service was installed in the system""" ]
  Fields = [
    """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """({event_code}4697)""",
    """({event_name}A service was installed in the system)""",
    """\sComputerName=(|({host}.+?))(\s+\w+=|\s*$)""",
    """\sKeywords=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """Security ID:\s*(|({user_sid}.+?))\s*Account Name:\s*(|({user}.+?))\s*Account Domain:\s*(|({domain}.+?))\s*Logon ID:\s*(|({logon_id}.+?))\s*Service Information:""",
    """Service Name:\s*(|({service_name}.+?))\s*Service File Name:\s*(|({process}({directory}.*?[\\\/]+)?({process_name}[^\\\/]+?)))\s*Service Type:\s*(|({service_type}.+?))\s*Service Start Type:\s*(|({service_start_type}.+?))\s*Service Account:""",
    """Service Account:\s*(({account_domain}[^\\]+)\\)?({account_name}.+?)\s*$""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```