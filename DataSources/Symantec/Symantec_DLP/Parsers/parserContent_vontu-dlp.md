#### Parser Content
```Java
{
Name = vontu-dlp
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "Policy Violated: ", "Endpoint: ", "Blocked: " ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\s({host}[^.\s]+)(\.\w+)*\s*(Message =)? ID:\s({alert_id}\d+)""",
      """\WPolicy Violated: ({alert_name}.+?)(,\s*\w+:|\s*$)""",
      """\WProtocol:\s+({alert_type}.+?)(,\s*\w+:|\s*$)""",
      """\WProtocol:\s+({protocol}.+?)(,\s*\w+:|\s*$)""",
      """\WRecipient:\s+(?:N\/A|({target}.+?))(,\s*\w+:|\s*$)""",
      """\WRecipient:\s+({account}[^@]+)@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\WRecipient:\s+\w+:\/+[^\/:]*?({top_domain}[^\.]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)[:\/,]""",
      """\WSender:\s+(?:N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user}[^@,]+))""",
      """\WSender:\s+({os}[^:]+):\/+({domain}[^/]+)\/({user}[^,]+)""",
      """\WSeverity:\s+({alert_severity}.+?)(,\s*\w+:|\s*$)""",
      """\WFilename:\s+(?:N\/A|({file_name}.+?))(,\s*\w+:|\s*$)""",
      """\WProtocol: FTP,.+?Subject:\s+(FTP\s+)?({file_name}.+?)\s*(\(|,)""",
      """\WProtocol: FTP,.+?Subject:.+?\(({bytes}\d+)""",
      """\WEndpoint:\s+(?:N\/A|({src_host}.+?))(,\s*\w+:|\s*$|\s*"|\s+\w+=)""",
      """\WBlocked:\s+({outcome}.+?)(,\s*\w+:|\s*$)""",
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "bytes->dlpFileSize", "outcome->dlpActionTaken"]
      NameTemplate = """Vontu DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```