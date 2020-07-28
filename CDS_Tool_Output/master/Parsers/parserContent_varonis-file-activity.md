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
      """Event Time:\s*({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """exabeam_host=({host}[^\s]+)""",
      """\sActing Object:\s*({domain}[^\\\s]+)\\""",
      """\sActing Object SAM Account Name:\s*({user}.+?)\s+File Server""",
      """\sIP Address/Host:\s*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))""",
      """\sEvent Type:\s*({accesses}.+?)\s*IP Address""",
      """\sAffected Object:\s*({file_name}.+?)\s*Event Type:""",
      """\sAffected Object:\s*.*(?=\.)({file_ext}.+?)\s*Event Type:""",
      """\sPath:\s*({file_path}.+?)\s*Affected Object:""",
      """\sPath:\s*({file_parent}.+?)\\[^\\]+\s+Affected Object:"""
    ]
    DupFields = [ "accesses->event_code" ]
  }
```