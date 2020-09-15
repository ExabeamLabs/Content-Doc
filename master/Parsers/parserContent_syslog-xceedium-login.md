#### Parser Content
```Java
{
Name = syslog-xceedium-login
  Vendor = Xceedium
  Product = Xceedium
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Message 18019:""", """logged in successfully""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"+\s*,""",
    ""","(|[- ]+|({src_ip}\S+?))",((\s*"([^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*"Message 18019:""",
    """"Message 18019:\s*User\s+({user}.+?)\s+logged in successfully""",
  ]
  DupFields = ["host->dest_host"]
}

{
  Name = syslog-xceedium-failed-login
  Vendor = Xceedium
  Product = Xceedium
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Message 18002:""", """Bad User ID""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """"+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"+\s*,""",
    ""","(|[- ]+|({src_ip}\S+?))",((\s*"([^"]|"")+")\s*,|[^",]+?,|\s*,){9}\s*"Message 18002:""",
    """Message 18002:\s*Bad User ID\s*\(\s*({user}.+?)\s*\)""",
    """({result_code}18002)""",
  ]
  DupFields = ["host->dest_host"]
}

  {
    Name = varonis-dlp-alert
    Vendor = Varonis
    Product = Data Security Platform
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ """Varonis alert:""","""Alert details:""" ]
    Fields = [
      """Event Time:\s*({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
      """exabeam_host=({host}[^\s]+)""",
      """Device hostname:\s*(|({host}[\w\-.]+))\s+Additional Data:""",
      """Acting Object:\s*({domain}[^\\\s]+)\\""",
      """Acting Object SAM Account Name:\s*({user}.+?)\s*File Server""",
      """IP Address/Host:\s*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))""",
      """Device IP address:\s*(|({dest_ip}[a-fA-F\d.:]+))\s*Device""",
      """Rule Name:\s*({alert_name}.+?)(?:\s+Severity|\s*Rule Storyline):""",
      """Event Type:\s*({alert_type}.+?)\s*(?:IP Address|Event Status)""",
      """Severity:\s*({alert_severity}\d+)""",
      """Affected Object:\s*({file_name}.+?)\s*Event Type:""",
      """Path:\s*({additional_info}.+?)\s*Affected Object:"""
    ]
  }
```