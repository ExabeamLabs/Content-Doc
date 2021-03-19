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
    """\W开始:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s*SymantecServer:""",
    """,本地:\s*({src_ip}[a-fA-F:\.\d]+),本地:\s*({src_port}\d+),本地:\s*({src_host}[\w\-\.]+),""",
    """,远程:\s*({dest_ip}[a-fA-F:\.\d]+),远程:\s*(|({dest_host}[\w\-\.]+)),远程:\s*({dest_port}\d+),""",
    """({protocol}[^,]+),({direction}[^,]+),开始:""",
    """\W应用程序:\s*({process}.*[\\\/]({process_name}[^\\\/,]+))""",
    """\W规则:\s*({event_name}[^,]+)""",
    """\W操作:\s*({outcome}[^,]+?)"*\s*$""",
    """\W用户:\s*({user}[^,]+),域:\s*({domain}[^,]+)"""
  ]
  DupFields = [ "outcome->action" ]
}
```