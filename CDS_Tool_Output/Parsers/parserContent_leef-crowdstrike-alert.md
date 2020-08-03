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
		"""\WscanResultName=(|({additional_info}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wdescription=(|({additional_info}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wurl=(|({alert_id}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wsev=({alert_severity}\d+)""",
		"""\WCrowdStrike\|(?:[^|]+\|){2}({alert_name}[^|]+)""",
		"""\Wresource=(|({host}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\WdevTime=({time}\d\d\d\d\-\d\d\-\d\d\s+\d\d\:\d\d\:\d\d)\s""",
		"""\Wcat=(|({alert_type}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wdomain=(?:|N\/A|({domain}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\WusrName=(|({user}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\WscanResultDetected=(|({scan_result_detected}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\WscanResultEngine=(|({scan_result_engine}.+?))(\||\t\w+=|["\s]*$)""",
		"""\WcommandLine=(|({command_line}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wmd5=(|({md5}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\Wsha256=(|({sha256_sum}[^\s]+?))(\||\t\w+=|["\s]*$)""",
		"""\W(docAccessedFileName|fileName)=(|({file_name}.+?))(\||\t\w+=|["\s]*$)""",
		"""\W(docAccessedFilePath|filePath)=(|({file_path}.+?))(\||\t\w+=|["\s]*$)""",
		"""\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
		"""\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
		"""\Wproto=(|({protocol}.+?))(\||\t\w+=|["\s]*$)""",
		"""\WsrcPort=({src_port}\d+)""",
		"""\WdstPort=({dest_port}\d+)""",
		"""\WdnsRequestDomain=(|({dns_request_domain}.+?))(\||\t\w+=|["\s]*$)""",
		"""\WrequestType=(|({dns_request_type}[^\s]+?))(\||\t\w+=|["\s]*$)"""
		"""\WfilePath=(|({process}[^\s]+\\+({process_name}[^\s]+)))""", 
    ]
}

{
  Name = crowdstrike-process-network
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """"event_simpleName":"""", """NetworkListenIP""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":"({time}\d+)""",
    """"LocalAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"LocalPort":"({dest_port}\d+)""",
    """"RemoteAddressIP4":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"RemotePort":"({dest_port}\d+)""",
    """"ConnectionDirection":"({direction}[^"]+)""",
    """"ContextProcessId":"({process_guid}[^"]+)""",
    """"event_simpleName":"({event_name}[^"]+)""",
    """"name":"({process_name}[^"]+)""",
    """"LocalAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
    """"RemoteAddressIP6":"(0.0.0.0|0:0:0:0:0:0:0:0|({dest_ip}[A-Fa-f:\d.]+))""",
  ]
}
```