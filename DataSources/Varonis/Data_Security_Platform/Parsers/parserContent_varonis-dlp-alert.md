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
      """Event Time:\s{0,100}({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """Device hostname:\s{0,100}(|({host}[\w\-.]{1,2000}))\s{1,100}Additional Data:""",
      """Acting Object:\s{0,100}({domain}[^\\\s]{1,2000})\\""",
      """Acting Object SAM Account Name:\s{0,100}({user}.+?)\s{0,100}File Server""",
      """IP Address/Host:\s{0,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
      """Device IP address:\s{0,100}(|({dest_ip}[a-fA-F\d.:]{1,2000}))\s{0,100}Device""",
      """Rule Name:\s{0,100}({alert_name}.+?)(?:\s{1,100}Severity|\s{0,100}Rule Storyline):""",
      """Event Type:\s{0,100}({alert_type}.+?)\s{0,100}(?:IP Address|Event Status)""",
      """Severity:\s{0,100}({alert_severity}\d{1,100})""",
      """Affected Object:\s{0,100}({file_name}.+?)\s{0,100}Event Type:""",
      """Path:\s{0,100}({additional_info}.+?)\s{0,100}Affected Object:"""
    ]
  }
```