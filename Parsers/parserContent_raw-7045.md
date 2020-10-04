#### Parser Content
```Java
{
Name = raw-7045
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-service-created"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """7045""", """A service was installed in the system.""" ]
  Fields = [
    """({event_name}A service was installed in the system)""",
    """({host}\S+)\sEvntSLog""",
    """\]\s+\w{3}\s({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """({event_code}7045)""",
    """\w{3}\s\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d:\s({domain}[^\\]+)\\(\\)?({user}[^\/]+)""",
    """Service Name:\s+({service_name}.+?)\s+Service File Name:""",
    """Service File Name:\s+(|-|({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/\s]+)))\s+Service Type:""",
    """Service Type:\s+({service_type}.+?)\s+Service Start Type:""",
    """Service Account:\s+({account_name}[^"\\]+)"""
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}

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
    """\sService Name:\s*(|({service_name}.+?))\s""",
    """\sService File Name:\s*"*(|({process}({directory}.*?[\\\/]+)?({process_name}[^\\\/"]+?)))"*\s""",
    """\sService Type:\s*(|({service_type}.+?))\s""",
    """\sService Start Type:\s*(|({service_start_type}.+?))\s""",
    """Service Account:\s*(({account_domain}[^\\]+)\\)?({account_name}.+?)\s*$""",
    """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```