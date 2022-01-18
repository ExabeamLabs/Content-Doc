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
      """\s({host}[^.\s]{1,2000})(\.\w+)*\s{0,100}(Message =)? ID:\s({alert_id}\d{1,100})""",
      """\WPolicy Violated: ({alert_name}.+?)(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WProtocol:\s{1,100}({alert_type}.+?)(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WProtocol:\s{1,100}({protocol}.+?)(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WRecipient:\s{1,100}(?:N\/A|({target}.+?))(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WRecipient:\s{1,100}({account}[^@]{1,2000})@({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\WRecipient:\s{1,100}\w+:\/+[^\/:]{0,2000}?({top_domain}[^\.]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)[:\/,]""",
      """\WSender:\s{1,100}(?:N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({user}[^@,]{1,2000}))""",
      """\WSender:\s{1,100}({os}[^:]{1,2000}):\/+({domain}[^/]{1,2000})\/({user}[^,]{1,2000})""",
      """\WSeverity:\s{1,100}({alert_severity}.+?)(,\s{0,100}\w+:|\s{0,100}$)""",
      """\sPATH:\s{1,100}(|({file_path}({file_parent}.*?[\\\/,]{1,2000})?({file_name}[^\\\/,]{1,2000}?(\.({file_ext}\w+))?)))(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WFilename:\s{1,100}(?:N\/A|({file_name}.+?))(,\s{0,100}\w+:|\s{0,100}$)""",
      """\WProtocol: FTP,.+?Subject:\s{1,100}(FTP\s{1,100})?({file_name}.+?)\s{0,100}(\(|,)""",
      """\WProtocol: FTP,.+?Subject:.+?\(({bytes}\d{1,100})""",
      """\WEndpoint:\s{1,100}(?:N\/A|({src_host}.+?))(,\s{0,100}\w+:|\s{0,100}$|\s{0,100}"|\s{1,100}\w+=)""",
      """\WBlocked:\s{1,100}({outcome}.+?)(,\s{0,100}\w+:|\s{0,100}$)""",
      """ViolatorsName:\s{1,100}(({user_fullname}\w+(,\s{0,100}\w+)+)|({user}\w+))(,\s{0,100}\w+:|\s{0,100}$)""",
      """ViolatorsUserID:\s{1,100}({user_id}[^,]{1,2000})(,\s{0,100}\w+:|\s{0,100}$)""",
      """ViolatorsEmail:\s{1,100}({user_email}[^@\s]{1,2000}@[^\s,]{1,2000})(,\s{0,100}\w+:|\s{0,100}$)""",
      """\sDEVICE_ID:\s{1,100}({device_id}[^,]{1,2000})(,\s{0,100}\w+:|\s{0,100}$)""",
      """\sApplication_name:\s{1,100}({process_name}[^,]{1,2000})(,\s{0,100}\w+:|\s{0,100}$)"""
    ]
    DupFields = ["user_email->sender", "target->recipients"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "bytes->dlpFileSize", "outcome->dlpActionTaken"]
      NameTemplate = """Vontu DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```