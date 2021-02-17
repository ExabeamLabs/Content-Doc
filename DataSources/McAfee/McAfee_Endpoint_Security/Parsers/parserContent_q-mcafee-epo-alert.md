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
          """[=\s^]DetectedUTC:\s"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
          """[=\s^]ServerID:\s"*({host}[^"]+)"""",
          """[=\s^]TargetHostName:\s"*(null|({src_host}[^"]+))"""",
          """[=\s^]TargetUserName:\s"*(null|SYSTEM|(({domain}[^\\\/\s]+)\\+)?({user}[^\\\/\s"]+))"""",
          """[=\s^]SourceUserName:\s"*(null|SYSTEM|(({domain}[^\\\/\s]+)\\+)?({user}[^\\\/\s"]+))"""",
          """[=\s^]ThreatCategory:\s"*(null|({threat_category}[^"]+))"""",
          """[=\s^]TargetFileName:\s"*(null|({malware_file_name}[^"]+))"""",
          """[=\s^]TargetProcessName:\s"*(null|({process}(({directory}[^"]*?)\\)?({process_name}[^"\\]*?)))"""",
          """[=\s^]ThreatEventID:\s"*({alert_id}[^"]+)""",
          """[=\s^]ThreatSeverity:\s"*({alert_severity}[^"]+)""",
          """[=\s^]ThreatName:\s"*(|_|6065|({alert_name}[^"]+))"* ThreatType:""",
          """[=\s^]ThreatType:\s"*(none|({alert_type}[^"]+))""",
          """[=\s^]ThreatActionTaken:\s"*(none|({action}[^"]+))""",
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