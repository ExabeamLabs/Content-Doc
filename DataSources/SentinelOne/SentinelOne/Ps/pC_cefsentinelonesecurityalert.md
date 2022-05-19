#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "CEF:", "|SentinelOne", "fileName =", "New active threat" ,"""threatClassification=Malware"""]
  Fields = [
    """\WdeviceAddress=({host}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WdeviceHostName =({host}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WoriginatorName =({src_host}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WeventDesc=({alert_name}[^\|]{1,2000}?)(\s{1,100}-\s{1,100}({src_host}[^\|]{1,2000}?))?((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WeventSeverity=({alert_severity}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\Wrt=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\WfileHash=(N/A|({md5}[^\|]{1,2000}?))((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WfilePath=(N/A|({file_path}[^\|]{1,2000}?))((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WfileName =({file_parent}[^\|]{0,2000}?\\(({user}[^\\\|]{1,2000})\\Desktop\\)?)({file_name}[^\\\|]{1,2000}?({file_ext}[^\\\|\.]{1,2000})?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WthreatClassification=({alert_name}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WthreatID=({alert_id}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceNetworkState=({src_net_status}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceOsRevision=({os_revision}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceOsType=({src_host_type}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceFqdn=({src_fqdn}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceDnsDomain=({src_domain}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceHostName =({src_host}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceAddress=({src_ip}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceNetInterfaceName =({src_interface}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """\WsourceMacAddress=({src_mac_address}[^\|]{1,2000}?)((\||\s{1,100})\w+=|\s{0,100}$)""",
    """threatClassification=({alert_type}[^\|]{1,2000})""", 
  ]
  DupFields = ["file_name->process_name", "file_path->process"]


}
```