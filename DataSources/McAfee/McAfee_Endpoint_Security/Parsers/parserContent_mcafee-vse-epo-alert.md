#### Parser Content
```Java
{
Name = mcafee-vse-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """AnalyzerName=""","""ThreatCategory=""" ]
    Fields = [
      """ReceivedUTC="?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """ServerID="?({host}[^"\|]+?)("|\||\s\w+=)""",
      """TargetHostName="?(?:|None|({src_host}[^"\|]+?)|)("|\||\s\w+=)""",     
      """TargetIPV4="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """TargetUserName="?(?:|None|(({domain}[^\\]+)\\+)?({user}[^"\|]+?))("|\||\s\w+=)""",
      """ThreatCategory="?({threat_category}[^"\|]+?)("|\||\s\w+=)""",
      """AutoGUID="?({alert_id}[^"]+?)("|\s+\w+=|\s*$)""",
      """ThreatSeverity="?({alert_severity}[^"\|]+?)("|\||\s\w+=)""",
      """ThreatName="?(?:|none|({alert_name}[^"\|]+?))("|\||\s\w+=)""",
      """ThreatType="?(?:|none|({alert_type}[^"\|]+?))("|\||\s\w+=)""",
      """TargetFileName="?(?:|None|({malware_url}.+?\\({malware_file_name}[^\\]+?)))("|\||\s\w+=)""",
      """OSType="({os}[^"]+)"""",
      """TargetProcessName="?(?:|none|({process_name}[^"\|]+?))("|\||\s\w+=)""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```