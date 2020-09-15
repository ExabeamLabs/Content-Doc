#### Parser Content
```Java
{
Name = eset-scan-activity
  Vendor = ESET
  Product = ESET Endpoint Security
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Scan ID:""" , """End Time:""", """Computer:""", """Domain Name:""", """User1:"""]
  Fields =[
  """({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
  """Scan ID:\s*({scan_id}\d+)""",
  """Computer:\s*({host}[^,]+)""",
  """IP Address:\s*({src_ip}[^,]+)""",
  """Server Name:\s*({dest_host}[^.]+)""",
  """User1:\s*({user}[^,]+)""",
  """Group Name:\s({group}[^,]+)"""
  ]
}

{
  Name = symantec-message-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss"
  Conditions = ["""protocol=""","""policy=""","""rules=""" ,"""file_name=""","""dlp_host=""" ]
  Fields = [
    """ocurred_on=({time}.+)\s(PM|AM|am|pm|Am|Pm), reported""",
    """sender=(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(N\/A|({user_email}[^,]+))""",
    """incident_id=({alert_id}\d+)""",
    """\sprotocol=({alert_type}[^,]+)""",
    """\spolicy=({alert_type}[^,]+)""",
    """\sseverity=({alert_severity}[^,]+)""",
    """\srules=({alert_name}[^,\)]+\)?)""",
    """\sdlp_host=({host}[^,]+)""",
    """blocked=({outcome}[^,]+)""",
    """recipients=({target}.+), severity=""",
    """file_name=({file_name}[^,]+)\s*""",
    """endpoint_machine_ip=({src_ip}[^,]+)""",
    """endpoint_user_id=({domain}[^\\]+)\\({user}[^,]+)"""
   ]
}

{
   Name = syslog-symantec-dlp-alert-6
   Vendor = Symantec
   Product = Symantec DLP
   Lms = Direct
   DataType = "dlp-alert"
   TimeFormat = "MMM dd, yyyy HH:mm:ss"
   Conditions = [  """,incident_id=""", """,block=""", """,policy=""", """,monitor_name=""", """,subject="""   ]
   Fields = [
     """\w+\s*\d+\s*\d+:\d+:\d+\s+({host}[^\s]+)\s+application""",
     """occurred_on="+(({time}.+?)\s+(:?AM|PM|am|pm))""",
     """incident_id="+({alert_id}[^"]+)""",
     """subject="+({subject}.+?)\s*"""",
     """policy_rules="+({alert_type}[^"]+)""",
     """protocol="+({protocol}[^"]+)""",
     """severity="+({alert_severity}[^"]+)""",
     """(policy|Policy)="+({alert_name}[^"]+)""",
     """sender="+(({sender}[^"@]+@[^"@]+)|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|(WinNT:\/+)?({domain}[^\\\/]+)(\\|\/)({user}[^"]+))"+""",     
     """block="+({outcome}[^"]+)""",
     """recipients="+((({target}http.+?)"+)|({recipients}({recipient}[^,"]+)[^"]*)"+)""",
     """attachment="+({attachments}[^"]+)\s+""",
     """match_count="+({match_count}[^"]+)""",
     ]
}

{
  Name = symantec-network-connection
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SymantecServer""", """User Name: """, """Rule: """ ]
  Fields = [
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s""",
    """SymantecServer:\s*({src_host}[^,]+?)\s*(,|$)"""
    """Local Host IP:\s*({src_ip}[^,]+)""",
    """Local Port:\s*({src_port}\d+)""",
    """Local Host MAC:\s*({src_mac}[^,\s]+)""",
    """Remote Host IP:\s*({dest_ip}[^,\s]+)""",
    """Remote Host Name:\s*({dest_host}[^,\s]+)""",
    """Remote Port:\s*({dest_port}\d+)""",
    """Remote Host MAC:\s*({dest_mac}[^,\s]+)""",
    """({protocol}[^,\s]+),({direction}Inbound|Outbound)""",
    """Begin:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,\s*Application:\s*({process}({directory}[^,]*?[\\\/]+)({process_name}[^,\\\/]+)),"""
    """User Name:\s*(SYSTEM|none|NETWORK|LOCAL|({user}[^\s,]+))""",
    """Rule:\s+(?:|({rule}[^,]+)),""",
    """Domain Name:\s*({domain}[^\s,]+)""",
    """Action:\s*({action}[^\s,]+)""",
    """SHA-256:\s*({sha256}[^\s,]+)""",
    """MD-5:\s*({md5}[^\s,]+)""",
  ]
}

${SymantecParserTemplates.symantec-critical-sys-protection}{
  Name = symantec-account-switch-failed
  DataType = "account-switch"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """failed SU to """ ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """To Username:\s*({account}[^"\s]+)""",
    """({outcome}(F|f)ailed)""",
    """Event source:\s*({process_name}[^"]+?)\s*From""",
    """({event_name}failed SU to [^"]+?)\s*Event"""
  ]
}
```