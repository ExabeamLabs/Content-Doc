#### Parser Content
```Java
{
Name = symantec-security-alert-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ SymantecServer: """, """Event Description:""", """Web Attack:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+SymantecServer:\s*({src_host}[^,]+)""",
    """,\s*Event Description:\s*({event_desc}[^,]+)""",
    """,\s*User:\s*({user}[^,]+)""",
    """,\s*Local Host IP:\s*(0.0.0.0|({local_host_ip}[^,]+))""",
    """,\s*Local Host MAC:\s*({local_host_mac}[^,]+)""",
    """,\s*Remote Host IP:\s*(0.0.0.0|({dest_ip}[^,]+))""",
    """,\s*Remote Host MAC:\s*({dest_mac}[^,]+)""",
    """,\s*Occurrences:\s*({occurrences}[^,]+)""",
    """,\s*Application:\s*({process}({directory}[^,]*?[\\\/]+)({process_name}[^,\\\/]+)),""",
    """,\s*Location:\s*({location}[^,]+)""",
    """,\s*Domain:\s*({domain}[^,]+)""",
    """,\s*Local Port:\s*(0|({src_port}\d+))""",
    """,\s*Remote Port:\s*(0|({dest_port}\d+))""",
    """,\s*CIDS Signature string:\s*({alert_name}[^,]+)""",
    """,\s*Intrusion URL:\s*({malware_url}[^,]+)""",
  ]
}
```