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
      """\Wcat=({threat_category}[^=]+?)\s{0,100}(\w+=|$)""",
      """\Wsev=({alert_severity}\d{1,100})""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
      """threatType=({alert_type}[^=]+?)\s{0,100}(\w+=|$)""",
      """\|ESET\|(?:[^\|]+\|){2}({alert_type}[^\|]+)""",
      """threatName=({alert_name}[^=]+?)\s{0,100}(\w+=|$)""",
      """eventDesc=({alert_name}[^=]+?)\s{0,100}(\w+=|$)""",
      """objectUri=({malware_url}[^=]+?)\s{0,100}(\w+=|$)""",
      """actionTaken=({action}[^=]+?)\s{0,100}(\w+=|$)""",
      """accountName=((({domain}[^\\=]+?)\\+)?({user}[^=]+?))\s{0,100}(\w+=|$)""",
      """engineVersion=({engine_version}\d{1,100})""",
      """objectType=({object_type}[^=]+?)\s{0,100}(\w+=|$)""",
      """threatHandled=({threat_handled}\d{1,100})""",
      """needRestart=({need_restart}\d{1,100})""",
      """circumstances=({circumstances}[^=]+?)\s{0,100}(\w+=|$)""",
      """firstseen=({firstseen}[^=]+?)\s{0,100}(\w+=|$)""",
      """hash=({sha256}[^\s]+)"""
    ]
    DupFields = ["action->additional_info", "host->dest_host", "malware_url->process_name"]
  }
```