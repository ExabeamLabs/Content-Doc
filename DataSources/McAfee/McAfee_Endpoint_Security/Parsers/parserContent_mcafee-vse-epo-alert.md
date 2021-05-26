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
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """ReceivedUTC="?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """ServerID="?({host}[^"\|]{1,2000}?)("|\||\s\w+=)""",
      """TargetHostName="?(?:|None|({src_host}[^"\|]{1,2000}?)|)("|\||\s\w+=)""",     
      """TargetIPV4="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """TargetUserName="?(?:|None|(({domain}[^\\]{1,2000})\\+)?({user}[^"\|]{1,2000}?))("|\||\s\w+=)""",
      """ThreatCategory="?({threat_category}[^"\|]{1,2000}?)("|\||\s\w+=)""",
      """AutoGUID="?({alert_id}[^"]{1,2000}?)("|\s{1,100}\w+=|\s{0,100}$)""",
      """ThreatSeverity="?({alert_severity}[^"\|]{1,2000}?)("|\||\s\w+=)""",
      """ThreatName="?(?:|none|({alert_name}[^"\|]{1,2000}?))("|\||\s\w+=)""",
      """ThreatType="?(?:|none|({alert_type}[^"\|]{1,2000}?))("|\||\s\w+=)""",
      """TargetFileName="?(?:|None|({malware_url}.+?\\({malware_file_name}[^\\]{1,2000}?)))("|\||\s\w+=)""",
      """OSType="({os}[^"]{1,2000})"""",
      """TargetProcessName="?(?:|none|({process_name}[^"\|]{1,2000}?))("|\||\s\w+=)""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```