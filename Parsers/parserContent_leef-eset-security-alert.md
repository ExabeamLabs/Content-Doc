#### Parser Content
```Java
{
Name = leef-eset-security-alert
    Vendor = ESET
    Product = ESET Endpoint Security
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ """LEEF:""", """|ESET|RemoteAdministrator|""","""cat=ESET Threat Event""","""threatType=""" ]
    Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """deviceName=({host}[^\s]+)\s""",
      """\Wcat=({threat_category}[^=]+?)\s*(\w+=|$)""",
      """\Wsev=({alert_severity}\d+)""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
      """threatType=({alert_type}[^=]+?)\s*(\w+=|$)""",
      """\|ESET\|(?:[^\|]+\|){2}({alert_type}[^\|]+)""",
      """threatName=({alert_name}[^=]+?)\s*(\w+=|$)""",
      """eventDesc=({alert_name}[^=]+?)\s*(\w+=|$)""",
      """objectUri=({malware_url}[^=]+?)\s*(\w+=|$)""",
      """actionTaken=({action}[^=]+?)\s*(\w+=|$)""",
      """accountName=((({domain}[^\\=]+?)\\+)?({user}[^=]+?))\s*(\w+=|$)""",
      """engineVersion=({engine_version}\d+)""",
      """objectType=({object_type}[^=]+?)\s*(\w+=|$)""",
      """threatHandled=({threat_handled}\d+)""",
      """needRestart=({need_restart}\d+)""",
      """circumstances=({circumstances}[^=]+?)\s*(\w+=|$)""",
      """firstseen=({firstseen}[^=]+?)\s*(\w+=|$)"""
    ]
    DupFields = ["action->additional_info", "host->dest_host", "malware_url->process_name"]
  }
```