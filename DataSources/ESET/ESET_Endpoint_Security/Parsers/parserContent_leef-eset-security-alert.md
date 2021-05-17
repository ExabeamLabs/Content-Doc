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
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """deviceName=({host}[^\s]{1,2000})\s""",
      """\Wcat=({threat_category}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wsev=({alert_severity}\d{1,100})""",
      """\WdevTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
      """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
      """threatType=({alert_type}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\|ESET\|(?:[^\|]{1,2000}\|){2}({alert_type}[^\|]{1,2000})""",
      """threatName=({alert_name}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """eventDesc=({alert_name}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """objectUri=({malware_url}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """actionTaken=({action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """accountName=((({domain}[^\\=]{1,2000}?)\\+)?({user}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
      """engineVersion=({engine_version}\d{1,100})""",
      """objectType=({object_type}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """threatHandled=({threat_handled}\d{1,100})""",
      """needRestart=({need_restart}\d{1,100})""",
      """circumstances=({circumstances}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """firstseen=({firstseen}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """hash=({sha256}[^\s]{1,2000})"""
    ]
    DupFields = ["action->additional_info", "host->dest_host", "malware_url->process_name"]
  }
```