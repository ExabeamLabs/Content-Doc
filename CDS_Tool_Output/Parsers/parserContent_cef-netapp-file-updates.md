#### Parser Content
```Java
{
Name = cef-netapp-file-updates
  Product = NetApp
  DataType = file-operations
  Conditions = [ """|NetApp|NetApp-Security-Auditing|""", """CEF:""", """app=CIFS"""]
}



{
  Name = weblogin-app-activity-1
  Product = Weblogin
  Vendor = Weblogin
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "web-activity"
  Conditions = [ """status=REDIRECT""", """sub=http""", """uniq=""", """realm=""", """authref=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """:\d+\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).*?user=(\s|({user}[^\s]+))\s*ip=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sstatus=({action}[^\s]+)\s*sub=(\s|({full_url}({protocol}http|https):({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?)|({sub_status}.*?)\suniq).*?authref=({request_cookie}[^\s]+)\s*wl_authref=({private_cookie}[^\s]+)\s*realm=(\s|({web_domain}[^\s]+))"""
    """=http.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""
 ]

}

{
  Name = cef-tenable-security-alert
  Vendor = Tenable.io
  Product = Tenable.io
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """dpriv=VULNERABILITY""","""destinationServiceName=Tenable.io""", """ cat=security-alert """ ]
  Fields = [
    """\s({host}[\w\-.]+)\s+Skyformation""",
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