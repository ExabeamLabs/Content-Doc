#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-2
  Conditions = [ """CEF:""", """|Symantec|""", """|sep_proxy_insight_event|""" ]
  Fields = ${SymantecParserTemplates.cef-symantec-sep-alert.Fields}[
    """({host}[\w.\-]+)\s+sep_proxy_insight_event:""",
  ]
}
cef-symantec-sep-alert = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\WinternalHost=(({src_ip}[a-fA-F\d.:]+)|({src_host}[^=]+?))(\s+\w+=|\s*$)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]+)""",
    """\Wmd5(=|":")({md5}[^="]+?)("|\s+\w+=|\s*$)""",
    """\Wuser_name=({user}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wfname=({malware_file_name}[^=]+?)(\s+\w+=|\s*$)""",
    """"feature_name":"({alert_type}[^"]+)""",
  ]

```