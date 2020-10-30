#### Parser Content
```Java
{
Name = cef-tenable-security-alert
  Vendor = Tenable.io
  Product = Tenable.io
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """dpriv=VULNERABILITY""","""destinationServiceName=Tenable.io""", """ cat=security-alert """ ]
  Fields = [
    """\WflexString1=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wext_pluginFamily=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wext_pluginName=(|({scan_name}.+?))(\s+\w+=|\s*$)""",
    """\Wext_severity=(|({alert_severity}.+?))(\s+\w+=|\s*$)""",
    """\WflexString2=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\Wext_assetIp=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_netBios=(|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\Wext_solution=(|({remediation}.+?))(\s+\w+=|\s*$)""",
    """\Wext_pluginOutput=(|\s*({outcome}.+?))(\s+\w+=|\s*$)""",
    """\Wext_startScanDateTime=(|({start_scan_time}.+?))(\s+\w+=|\s*$)""",
    """\Wext_endScanDateTime=(|({end_scan_time}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({scan_type}.+?))(\s+\w+=|\s*$)""",
    """\Wext_os=(|({os}.+?))(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "start_scan_time->time" ]
}
```