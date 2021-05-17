#### Parser Content
```Java
{
Name = q-mcafee-epo-alert
        Vendor = McAfee
        Product = McAfee Endpoint Security
        Lms = QRadar
        DataType = "alert"
        TimeFormat = "yyyy-MM-dd HH:mm:ss"
        Conditions = [ """AnalyzerName: ""","""ThreatCategory:""" ]
        Fields = [
          """[=\s^]DetectedUTC:\s"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
          """[=\s^]ServerID:\s"{0,20}({host}[^"]{1,2000})"""",
          """[=\s^]TargetHostName:\s"{0,20}(null|({src_host}[^"]{1,2000}))"""",
          """[=\s^]TargetUserName:\s"{0,20}(null|SYSTEM|(({domain}[^\\\/\s]{1,2000})\\+)?({user}[^\\\/\s"]{1,2000}))"""",
          """[=\s^]SourceUserName:\s"{0,20}(null|SYSTEM|(({domain}[^\\\/\s]{1,2000})\\+)?({user}[^\\\/\s"]{1,2000}))"""",
          """[=\s^]ThreatCategory:\s"{0,20}(null|({threat_category}[^"]{1,2000}))"""",
          """[=\s^]TargetFileName:\s"{0,20}(null|({malware_file_name}[^"]{1,2000}))"""",
          """[=\s^]TargetProcessName:\s"{0,20}(null|({process}(({directory}[^"]{0,2000}?)\\)?({process_name}[^"\\]{0,2000}?)))"""",
          """[=\s^]ThreatEventID:\s"{0,20}({alert_id}[^"]{1,2000})""",
          """[=\s^]ThreatSeverity:\s"{0,20}({alert_severity}[^"]{1,2000})""",
          """[=\s^]ThreatName:\s"{0,20}(|_|6065|({alert_name}[^"]{1,2000}))"{0,20} ThreatType:""",
          """[=\s^]ThreatType:\s"{0,20}(none|({alert_type}[^"]{1,2000}))""",
          """[=\s^]ThreatActionTaken:\s"{0,20}(none|({action}[^"]{1,2000}))""",
        ]
        DupFields = ["directory->process_directory"]
        SOAR {
          IncidentType = "malware"
          DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "alert_type->description", "action->description"]
          NameTemplate = """Mcafee Alert ${alert_name} found"""
          ProjectName = "SOC"
          EntityFields = [
            {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```