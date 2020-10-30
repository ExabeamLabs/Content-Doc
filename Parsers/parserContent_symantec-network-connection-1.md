#### Parser Content
```Java
{
Name = symantec-network-connection-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,User Name: """, """,Action: """, """,Domain Name: """, """,Rule: """, """,Location: """ ]
  Fields = [
    """({direction}Inbound|Outbound),Begin:\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+\d+:\d+,\s+({host}[^,]+)""",
    """Local Host IP:\s+(0.0.0.0|({src_ip}[^,]+))""",
    """Local Port:\s+({src_port}\d+)""",
    """Local Host MAC:\s+({src_mac}[^,\s]+)""",
    """Remote Host IP:\s+(0.0.0.0|({dest_ip}[^,\s]+))""",
    """Remote Host Name:\s+({dest_host}[^,\s]+)""",
    """Remote Port:\s+({dest_port}\d+)""",
    """Remote Host MAC:\s+({dest_mac}[^,\s]+)""",
    """User Name:\s+(SYSTEM|none|NETWORK|LOCAL|({user}[^\s,]+))""",
    """Application:\s+({process}({directory}[^,]*?[\\\/]+)({process_name}[^,\\\/]+)),"""
    """Rule:\s+(?:|({rule}[^,]+)),""",
    """Domain Name:\s+({domain}[^\s,]+)""",
    """Action:\s+({action}[^\s,]+)""",
    """SHA-256:\s+({sha256}[^\s,]+)""",
    """MD-5:\s+({md5}[^\s,]+)""",
  ]
}
```