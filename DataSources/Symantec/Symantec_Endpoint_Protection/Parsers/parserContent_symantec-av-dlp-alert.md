#### Parser Content
```Java
{
Name = symantec-av-dlp-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Local:""", """Remote:""", """Rule:""", """Action:""", """Begin:""", """End:""", """Occurrences:""", """Application:""" ]
  Fields = [
    """\WBegin:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """({host}[\w\-\.]+)\s*SymantecServer:""",
    """,Local:\s*({src_ip}[a-fA-F:\.\d]+),Local:\s*({src_port}\d+),Local:\s*(0.0.0.0|({=src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-\.]+)),""",
    """,Remote:\s*(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})),Remote:\s*(|({dest_host}[\w\-\.]+)),Remote:\s*({dest_port}\d+),""",
    """({protocol}[^,]+),({direction}[^,]+),Begin:""",
    """\WApplication:\s*({process}({directory}[^",]+?)?([\\\/]+({process_name}[^\\\/,"]+)))\s*,""",
    """\WRule:\s*({event_name}[^,]+)""",
    """\WAction:\s*({outcome}[^,]+?)"*\s*$""",
    """\WUser:\s*(none|({user}[^,]+)),Domain:\s*(|({domain}[^,]+?))\s*,"""
  ]
  DupFields = [ "outcome->action" ]
}
```