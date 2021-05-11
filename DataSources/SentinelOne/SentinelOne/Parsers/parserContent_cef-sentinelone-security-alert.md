#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "CEF:", "|SentinelOne", "fileName=", "New active threat" ,"""threatClassification=Malware"""]
  Fields = [
    """\WdeviceAddress=({host}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WdeviceHostName=({host}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WoriginatorName=({src_host}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WeventDesc=({alert_name}[^\|]+?)(\s{1,100}-\s{1,100}({src_host}[^\|]+?))?((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WeventSeverity=({alert_severity}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\WfileHash=(N/A|({md5}[^\|]+?))((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WfilePath=(N/A|({file_path}[^\|]+?))((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WfileName=({file_parent}[^\|]*?\\(({user}[^\\\|]+)\\Desktop\\)?)({file_name}[^\\\|]+?({file_ext}[^\\\|\.]+)?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WthreatClassification=({alert_name}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WthreatID=({alert_id}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceNetworkState=({src_net_status}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceOsRevision=({os_revision}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceOsType=({src_host_type}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceFqdn=({src_fqdn}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceDnsDomain=({src_domain}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceHostName=({src_host}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceAddress=({src_ip}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceNetInterfaceName=({src_interface}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceMacAddress=({src_mac_address}[^\|]+?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """threatClassification=({alert_type}[^\|]+)""", 
  ]
  DupFields = ["file_name->process_name", "file_path->process"]
}
```