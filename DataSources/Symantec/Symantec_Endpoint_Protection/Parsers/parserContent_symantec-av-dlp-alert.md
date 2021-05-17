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
    """\WBegin:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d((\+|\-)\d\d:\d\d)?)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\-\.]{1,2000})\s{0,100}SymantecServer:""",
    """,Local:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),Local:\s{0,100}({src_port}\d{1,100}),Local:\s{0,100}(0.0.0.0|({=src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-\.]{1,2000})),""",
    """,Remote:\s{0,100}(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})),Remote:\s{0,100}(|({dest_host}[\w\-\.]{1,2000})),Remote:\s{0,100}({dest_port}\d{1,100}),""",
    """({protocol}[^,]{1,2000}),({direction}[^,]{1,2000}),Begin:""",
    """\WApplication:\s{0,100}({process}({directory}[^",]{1,2000}?)?([\\\/]{1,2000}({process_name}[^\\\/,"]{1,2000})))\s{0,100}
```