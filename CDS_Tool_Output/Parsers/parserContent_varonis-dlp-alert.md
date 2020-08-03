#### Parser Content
```Java
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