#### Parser Content
```Java
{
Name = leef-eset-security-alert
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "LEEF:1.0|ESET|RemoteAdministrator|","cat=ESET","threatType=" ]
    Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """(\s|\|)cat=({threat_category}.+?)\s*(\w+=|$)""",
      """(\s|\|)sev=({alert_severity}\d+)""",
      """(\s|\|)devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """(\s|\|)src=({src_ip}(\d{1,3}\.){3}\d{1,3})""",
      """(\s|\|)threatType=({alert_type}.+?)\s*(\w+=|$)""",
      """(\s|\|)threatName=({alert_name}.+?)\s*(\w+=|$)""",
      """(\s|\|)objectUri=({malware_url}.+?)\s*(\w+=|$)""",
      """(\s|\|)actionTaken=({action}.+?)\s*(\w+=|$)""",
      """(\s|\|)accountName=((({domain}.+?)\\+)?({user}.+?))\s*(\w+=|$)""",
    ]
    DupFields = ["action->additional_info", "host->dest_host", "malware_url->process_name"]
  }
```