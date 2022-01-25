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
    """\sComputerName=(|({host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sKeywords=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Security ID:\s{0,100}(|({user_sid}.+?))\s{0,100}Account Name:\s{0,100}(|({user}.+?))\s{0,100}Account Domain:\s{0,100}(|({domain}.+?))\s{0,100}Logon ID:\s{0,100}(|({logon_id}.+?))\s{0,100}Service Information:""",
    """\sService Name:\s{0,100}(|({service_name}.+?))\s""",
    """\sService File Name:\s{0,100}"{0,20}(|({process}({directory}.*?[\\\/]{1,2000})?({process_name}[^\\\/"]{1,2000}?)))"{0,20}\s""",
    """\sService Type:\s{0,100}(|({service_type}.+?))\s""",
    """\sService Start Type:\s{0,100}(|({service_start_type}.+?))\s""",
    """Service Account:\s{0,100}(({account_domain}[^\\]{1,2000})\\)?({account_name}.+?)\s{0,100}$""",
    """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```