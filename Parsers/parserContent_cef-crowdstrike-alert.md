#### Parser Content
```Java
{
Name = cef-crowdstrike-alert
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ "CEF", """|CrowdStrike|FalconHost|""" ]
    Fields = [ 
      """exabeam_host=({host}[\w\-.]+)""",
      """\srt=({time}\d+)""",
      """({host}[\w.\-]+) CEF:""",
      """\s({host}[^\s]+)\s+CrowdStrike Falcon""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """(\s|\|)(s|d)ntdom=(?:N\/A|({domain}[^\s]+))""",      
      """(\s|\|)suser=(?:N\/A|({user}.+?))(@({domain}.+?))?\s+(\w+=|$)""",
      """(\s|\|)duser=(?:N\/A|({user}.+?))(@({domain}.+?))?\s+(\w+=|$)""",
      """(\s|\|)dhost=({src_host}[^\s]+)""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
	  """(\s|\|)shost=.+?(\s|\|)dhost=({dest_host}[^\s]+)""",
      """(\s|\|)dhost=({dest_host}[^\s]+).+?(\s|\|)shost=""",
      """(\s|\|)src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """(\s|\|)dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """CrowdStrike\|([^|]+\|){3}({alert_name}[^|]+)""",
      """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
      """CrowdStrike\|([^|]+\|){4}({alert_severity}[^|]+)""",
	  """(\s|\|)cat=({alert_name}.+?)\s+(\w+=|$)""",
      """(\s|\|)cs3=({alert_name}.+?)\s+\w+=.*?cs3Label=ScanResultName""",
      """cs3Label=ScanResultName.*?cs3=({alert_name}.+?)\s+(\w+=|$)""",
      """(\s|\|)cs1=({alert_name}.+?)\s+\w+=.*?cs1Label=ScanResultName""",
      """cs1Label=ScanResultName.*?cs1=({alert_name}.+?)\s+(\w+=|$)""",
      """(\s|\|)msg=({additional_info}.+?)\s+(\w+=|$)""",
      """(\s|\|)fname=({file_name}.+?)\s+(\w+=|$)""",
      """(\s|\|)filePath=({file_path}.+?)\s+(\w+=|$)""",
      """(\s|\|)cs1=("+)?({command_line}.+?)("+)?\s\w+=.*(?=cs1Label=CommandLine)""",
      """(?=cs1Label=CommandLine).*cs1=("+)?({command_line}.+?)("+)?\s+(\w+=|$)""",
      """(\s|\|)cs5=("+)?({command_line}.+?)("+)?\s\w+=.*(?=cs5Label=CommandLine)""",
      """(?=cs5Label=CommandLine).*cs5=("+)?({command_line}.+?)("+)?\s+(\w+=|$)""",
      """(\s|\|)cs6=({additional_info}.+?)\s\w+=.*(?=cs6Label=FalconHostLink)""",
      """(?=cs6Label=FalconHostLink).*cs6=({additional_info}.+?)\s+(\w+=|$)"""
    ]
  }
  
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