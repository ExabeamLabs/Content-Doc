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
          """[=\s^]ServerID:\s"{0,20}({host}[^"]+)"""",
          """[=\s^]TargetHostName:\s"{0,20}(null|({src_host}[^"]+))"""",
          """[=\s^]TargetUserName:\s"{0,20}(null|SYSTEM|(({domain}[^\\\/\s]+)\\+)?({user}[^\\\/\s"]+))"""",
          """[=\s^]SourceUserName:\s"{0,20}(null|SYSTEM|(({domain}[^\\\/\s]+)\\+)?({user}[^\\\/\s"]+))"""",
          """[=\s^]ThreatCategory:\s"{0,20}(null|({threat_category}[^"]+))"""",
          """[=\s^]TargetFileName:\s"{0,20}(null|({malware_file_name}[^"]+))"""",
          """[=\s^]TargetProcessName:\s"{0,20}(null|({process}(({directory}[^"]*?)\\)?({process_name}[^"\\]*?)))"""",
          """[=\s^]ThreatEventID:\s"{0,20}({alert_id}[^"]+)""",
          """[=\s^]ThreatSeverity:\s"{0,20}({alert_severity}[^"]+)""",
          """[=\s^]ThreatName:\s"{0,20}(|_|6065|({alert_name}[^"]+))"{0,20} ThreatType:""",
          """[=\s^]ThreatType:\s"{0,20}(none|({alert_type}[^"]+))""",
          """[=\s^]ThreatActionTaken:\s"{0,20}(none|({action}[^"]+))""",
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