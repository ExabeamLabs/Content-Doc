#### Parser Content
```Java
{
Name = u-mcafee-epo-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Sumo
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """<AnalyzerName>""","""<AnalyzerVersion>""","""<Analyzer>""" ]
    Fields = [
      """<(DetectedUTC|GMTTime)>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """({host}[\w\-.]+)\s+EPOEvents""",
      """<TargetHostName>({src_host}[^<]+)""",
      """<MachineName>({src_host}[^<]+)""",
      """<IPAddress>(::1|({src_ip}[^<]+))""",
      """<SourceUserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(S(ystem|YSTEM)|({user}[^<\\\s]+))<\/SourceUserName>""",
      """<DomainName>({domain}[^<]+)""",
      """<UserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(SYSTEM|({user}[^<\\\s]+))<\/UserName>""",
      """<TargetUserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(SYSTEM|({user}[^<\\\s]+))<\/TargetUserName>""",
      """<ThreatCategory>({threat_category}[^<]+)""",
      """<ThreatEventID>({alert_id}[^<]+)""",
      """<ThreatSeverity>({alert_severity}[^<]+)""",
      """<ThreatCategory>({alert_name}[^<]+)""",
      """<ThreatName>(?:(-|_)|({alert_name}[^<]+))<\/ThreatName>""",
      """<ThreatCategory>({alert_type}[^<]+)""",
      """<ThreatType>({alert_type}[^<]+)""",
      """<TargetFileName>({malware_url}.*?[\\\/]*\s*({malware_file_name}[^\s\\\/<][^\\\/<]*?))\\?<""",
      """<AnalyzerDetectionMethod>({additional_info}[^<]+)""",
      """<OSName>({os}[^<]+)""",
      """<ThreatActionTaken>(none|({outcome}[^<]+))""",
      """<AnalyzerName>(N\/A|({event_name}[^<]+))""",
      """<TaskName>({task_name}[^<]+)""",
      """<TargetPath>({process}({process_directory}[^<]*?)\s*(({process_name}[^\s<\\\/][^<\\\/]*?)?))<""",
      """<TargetName>\s*({process_name}[^\s<][^<]*?)<""",
      """<SourceProcessName>({src_process_name}[^<]+)<""",
      """<TargetHash>\s*({md5}[^\s<][^<]*)<""",
      """<Cleanable>({cleanable}[^<]+)<""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```