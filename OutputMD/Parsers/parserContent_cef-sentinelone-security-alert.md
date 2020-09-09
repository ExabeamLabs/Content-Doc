#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert
  Vendor = SentinelOne
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "CEF:", "|SentinelOne", "fileName=", "New active threat" ]
  Fields = [
    """\WdeviceAddress=({host}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WdeviceHostName=({host}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WoriginatorName=({src_host}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WeventDesc=({alert_name}[^\|]+?)(\s+-\s+({src_host}[^\|]+?))?((\||\s+)\w+=|\s*$)""",
    """\WeventSeverity=({alert_severity}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\Wrt=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\WfileHash=(N/A|({md5}[^\|]+?))((\||\s+)\w+=|\s*$)""",
    """\WfilePath=(N/A|({file_path}[^\|]+?))((\||\s+)\w+=|\s*$)""",
    """\WfileName=({file_parent}[^\|]*?\\(({user}[^\\\|]+)\\Desktop\\)?)({file_name}[^\\\|]+?({file_ext}[^\\\|\.]+)?)((\||\s+)\w+=|\s*$)""",
    """\WthreatClassification=({alert_name}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WthreatID=({alert_id}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceNetworkState=({src_net_status}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceOsRevision=({os_revision}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceOsType=({src_host_type}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceFqdn=({src_fqdn}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceDnsDomain=({src_domain}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceHostName=({src_host}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceAddress=({src_ip}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceNetInterfaceName=({src_interface}[^\|]+?)((\||\s+)\w+=|\s*$)""",
    """\WsourceMacAddress=({src_mac_address}[^\|]+?)((\||\s+)\w+=|\s*$)""",
  ]
}
```