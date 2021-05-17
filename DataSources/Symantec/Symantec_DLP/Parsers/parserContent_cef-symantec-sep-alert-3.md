#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-3
  Conditions = [ """CEF:""", """|Symantec|""", """|sep_proxy_sonar_event|""" ]
  Fields = ${SymantecParserTemplates.cef-symantec-sep-alert.Fields}[
    """({host}[\w.\-]{1,2000})\s{1,100}sep_proxy_sonar_event:""",
  ]
}
cef-symantec-sep-alert = {
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\WinternalHost=(({src_ip}[a-fA-F\d.:]{1,2000})|({src_host}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wmd5(=|":")({md5}[^="]{1,2000}?)("|\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser_name=({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=({malware_file_name}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"feature_name":"({alert_type}[^"]{1,2000})""",
  ]

```