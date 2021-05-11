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
    """exabeam_host=({host}[\w\-.]+)""",
    """\WscanResultName=(|({additional_info}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wdescription=(|({additional_info}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wurl=(|({url}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\WCrowdStrike\|(?:[^|]+\|){2}({alert_name}[^|]+)""",
    """\Wresource=(|({host}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d\s{1,100}\d\d\:\d\d\:\d\d)\s""",
    """\Wcat=(|({alert_type}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wdomain=(?:|N\/A|({domain}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WusrName=(|N\/A|({user_email}[^@=\|\s]+@[^"@\|\s=]+?)|({user}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WscanResultDetected=(|({scan_result_detected}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WscanResultEngine=(|({scan_result_engine}[^=|\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WcommandLine=(|({command_line}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wmd5=(|({md5}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wsha256=(|({sha256_sum}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\W(docAccessedFileName|fileName)=(|({file_name}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\W(docAccessedFilePath|filePath)=(|({file_path}.+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\Wproto=(|({protocol}[^=|\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdnsRequestDomain=(|({dns_request_domain}[^=|\s]+?))\s{0,100}(\||\w+=|["\s]*$)""",
    """\WrequestType=(|({dns_request_type}[^\s]+?))\s{0,100}(\||\w+=|["\s]*$)"""
    """\WfilePath=(|({process}[^\s]+\\+({process_name}[^\s]+)))""",
  ]
}
```