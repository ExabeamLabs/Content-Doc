#### Parser Content
```Java
{
Name = symantec-av-dlp-alert-cn
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ "本地:", "远程:", "规则:", "操作:" ]
  Fields = [
    """\W开始:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s{0,100}SymantecServer:""",
    """,本地:\s{0,100}({src_ip}[a-fA-F:\.\d]+),本地:\s{0,100}({src_port}\d{1,100}),本地:\s{0,100}({src_host}[\w\-\.]+),""",
    """,远程:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),远程:\s{0,100}(|({dest_host}[\w\-\.]+)),远程:\s{0,100}({dest_port}\d{1,100}),""",
    """({protocol}[^,]+),({direction}[^,]+),开始:""",
    """\W应用程序:\s{0,100}({process}.*[\\\/]({process_name}[^\\\/,]+))""",
    """\W规则:\s{0,100}({event_name}[^,]+)""",
    """\W操作:\s{0,100}({outcome}[^,]+?)"{0,20}\s{0,100}$""",
    """\W用户:\s{0,100}({user}[^,]+),域:\s{0,100}({domain}[^,]+)"""
  ]
  DupFields = [ "outcome->action" ]
}
```