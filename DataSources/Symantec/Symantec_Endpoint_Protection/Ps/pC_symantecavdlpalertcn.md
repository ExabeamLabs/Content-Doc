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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{0,100}SymantecServer:""",
    """,本地:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),本地:\s{0,100}({src_port}\d{1,100}),本地:\s{0,100}({src_host}[\w\-\.]{1,2000}),""",
    """,远程:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),远程:\s{0,100}(|({dest_host}[\w\-\.]{1,2000})),远程:\s{0,100}({dest_port}\d{1,100}),""",
    """({protocol}[^,]{1,2000}),({direction}[^,]{1,2000}),开始:""",
    """\W应用程序:\s{0,100}({process}.*[\\\/]({process_name}[^\\\/,]{1,2000}))""",
    """\W规则:\s{0,100}({event_name}[^,]{1,2000})""",
    """\W操作:\s{0,100}({outcome}[^,]{1,2000}?)"{0,20}\s{0,100}$""",
    """\W用户:\s{0,100}({user}[^,]{1,2000}),域:\s{0,100}({domain}[^,]{1,2000})"""
  ]
  DupFields = [ "outcome->action" ]
}
```