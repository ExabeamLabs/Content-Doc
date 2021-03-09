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
    """\WscanResultName=(|({additional_info}.+?))\s*(\||\w+=|["\s]*$)""",
    """\Wdescription=(|({additional_info}.+?))\s*(\||\w+=|["\s]*$)""",
    """\Wurl=(|({url}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\Wsev=({alert_severity}\d+)""",
    """\WCrowdStrike\|(?:[^|]+\|){2}({alert_name}[^|]+)""",
    """\Wresource=(|({host}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d\s+\d\d\:\d\d\:\d\d)\s""",
    """\Wcat=(|({alert_type}.+?))\s*(\||\w+=|["\s]*$)""",
    """\Wdomain=(?:|N\/A|({domain}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WusrName=(|N\/A|({user_email}[^@=\|\s]+@[^"@\|\s=]+?)|({user}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WscanResultDetected=(|({scan_result_detected}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WscanResultEngine=(|({scan_result_engine}[^=|\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WcommandLine=(|({command_line}.+?))\s*(\||\w+=|["\s]*$)""",
    """\Wmd5=(|({md5}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\Wsha256=(|({sha256_sum}[^\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\W(docAccessedFileName|fileName)=(|({file_name}.+?))\s*(\||\w+=|["\s]*$)""",
    """\W(docAccessedFilePath|filePath)=(|({file_path}.+?))\s*(\||\w+=|["\s]*$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\Wproto=(|({protocol}[^=|\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WsrcPort=({src_port}\d+)""",
    """\WdstPort=({dest_port}\d+)""",
    """\WdnsRequestDomain=(|({dns_request_domain}[^=|\s]+?))\s*(\||\w+=|["\s]*$)""",
    """\WrequestType=(|({dns_request_type}[^\s]+?))\s*(\||\w+=|["\s]*$)"""
    """\WfilePath=(|({process}[^\s]+\\+({process_name}[^\s]+)))""",
  ]
}
```