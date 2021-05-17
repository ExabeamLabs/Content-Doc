#### Parser Content
```Java
{
Name = varonis-file-activity
    Vendor = Varonis
    Product = Data Security Platform
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ """Acting Object SAM Account Name:""","""Changed Permissions:""" ]
    Fields = [
      """Event Time:\s{0,100}({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\sActing Object:\s{0,100}({domain}[^\\\s]{1,2000})\\""",
      """\sActing Object SAM Account Name:\s{0,100}({user}.+?)\s{1,100}File Server""",
      """\sIP Address/Host:\s{0,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
      """\sEvent Type:\s{0,100}({accesses}.+?)\s{0,100}IP Address""",
      """\sAffected Object:\s{0,100}({file_name}.+?)\s{0,100}Event Type:""",
      """\sAffected Object:\s{0,100}.*(?=\.)({file_ext}.+?)\s{0,100}Event Type:""",
      """\sPath:\s{0,100}({file_path}.+?)\s{0,100}Affected Object:""",
      """\sPath:\s{0,100}({file_parent}.+?)\\[^\\]{1,2000}\s{1,100}Affected Object:"""
    ]
    DupFields = [ "accesses->event_code" ]
  }
```