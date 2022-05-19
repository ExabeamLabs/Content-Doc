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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({host}[\w\-.]{1,2000})\s{1,100}EPOEvents""",
      """<TargetHostName>({src_host}[^<]{1,2000})""",
      """<MachineName>({src_host}[^<]{1,2000})""",
      """<IPAddress>(::1|({src_ip}[^<]{1,2000}))""",
      """<SourceUserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]{1,2000}))\\+)?(S(ystem|YSTEM)|({user}[^<\\\s]{1,2000}))<\/SourceUserName>""",
      """<DomainName>({domain}[^<]{1,2000})""",
      """<UserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]{1,2000}))\\+)?(SYSTEM|({user}[^<\\\s]{1,2000}))<\/UserName>""",
      """<TargetUserName>((NT-AUTORITÄT|AUTORIDADE NT|NT AUTHORITY|({domain}[^\\\s]{1,2000}))\\+)?(SYSTEM|({user}[^<\\\s]{1,2000}))<\/TargetUserName>""",
      """<ThreatCategory>({threat_category}[^<]{1,2000})""",
      """<ThreatEventID>({alert_id}[^<]{1,2000})""",
      """<ThreatSeverity>({alert_severity}[^<]{1,2000})""",
      """<ThreatCategory>({alert_name}[^<]{1,2000})""",
      """<ThreatName>(?:(-|_)|({alert_name}[^<]{1,2000}))<\/ThreatName>""",
      """<ThreatCategory>({alert_type}[^<]{1,2000})""",
      """<ThreatType>({alert_type}[^<]{1,2000})""",
      """<TargetFileName>({malware_url}[^=]{0,2000}?[\\\/]{0,2000}\s{0,100}({malware_file_name}[^\s\\\/<][^\\\/<]{0,2000}?))\\?<""",
      """<AnalyzerDetectionMethod>({additional_info}[^<]{1,2000})""",
      """<OSName>({os}[^<]{1,2000})""",
      """<ThreatActionTaken>(none|([^\._<]{1,2000}[\.|_]){0,256}({outcome}[^<]{1,2000}))<""",
      """<AnalyzerName>(N\/A|({event_name}[^<]{1,2000}))""",
      """<TaskName>({task_name}[^<]{1,2000})""",
      """<TargetPath>({process}({process_directory}[^<]{0,2000}?)\s{0,100}(({process_name}[^\s<\\\/][^<\\\/]{0,2000}?)?))<""",
      """<TargetName>\s{0,100}({process_name}[^\s<][^<]{0,2000}?)<""",
      """<SourceProcessName>({src_process_name}[^<]{1,2000})<""",
      """<TargetHash>\s{0,100}({md5}[^\s<][^<]{0,2000})<""",
      """<Cleanable>({cleanable}[^<]{1,2000})<""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "threat_category->malwareCategory", "alert_severity->sourceSeverity", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```