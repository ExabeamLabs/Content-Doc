#### Parser Content
```Java
{
Name = leef-crowdstrike-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|CrowdStrike|FalconHost|""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\WscanResultName=(|({additional_info}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wdescription=(|({additional_info}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wurl=(|({url}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\WCrowdStrike\|(?:[^|]{1,2000}\|){2}({alert_name}[^|]{1,2000})""",
    """\Wresource=(|({host}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d\s{1,100}\d\d\:\d\d\:\d\d)\s""",
    """\Wcat=(|({alert_type}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wdomain=(?:|N\/A|({domain}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WusrName=(|N\/A|({user_email}[^@=\|\s]{1,2000}@[^"@\|\s=]{1,2000}?)|({user}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WscanResultDetected=(|({scan_result_detected}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WscanResultEngine=(|({scan_result_engine}[^=|\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WcommandLine=(|({command_line}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wmd5=(|({md5}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wsha256=(|({sha256_sum}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\W(docAccessedFileName|fileName)=(|({file_name}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\W(docAccessedFilePath|filePath)=(|({file_path}.+?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wproto=(|({protocol}[^=|\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdnsRequestDomain=(|({dns_request_domain}[^=|\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)""",
    """\WrequestType=(|({dns_request_type}[^\s]{1,2000}?))\s{0,100}(\||\w+=|["\s]{0,2000}$)"""
    """\WfilePath=(|({process}[^\s]{1,2000}\\+({process_name}[^\s]{1,2000})))""",
  ]
}
```