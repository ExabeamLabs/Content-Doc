#### Parser Content
```Java
{
Name = symantec-network-connection
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SymantecServer""", """User Name: """, """Rule: """ ]
  Fields = [
    """\d\d:\d\d:\d\d (({host}[\w-]+)\s+)?SymantecServer: (({=host}[\w-]+),)?({src_host}[^,]+),Local Host IP:"""
    """Local Host IP:\s*({src_ip}[^,]+)""",
    """Local Port:\s*({src_port}\d+)""",
    """Local Host MAC:\s*({src_mac}[^,\s]+)""",
    """Remote Host IP:\s*({dest_ip}[^,\s]+)""",
    """Remote Host Name:\s*({dest_host}[^,\s]+)""",
    """Remote Port:\s*({dest_port}\d+)""",
    """Remote Host MAC:\s*({dest_mac}[^,\s]+)""",
    """({protocol}[^,\s]+),({direction}Inbound|Outbound)""",
    """Begin:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,\s*Application:\s*({process}({directory}[^,]*?[\\\/]+)({process_name}[^,\\\/]+)),"""
    """User Name:\s*(SYSTEM|none|NETWORK|LOCAL|({user}[^\s,]+))""",
    """Rule:\s+(?:|({rule}[^,]+)),""",
    """Domain Name:\s*({domain}[^\s,]+)""",
    """Action:\s*({action}[^\s,]+)""",
    """SHA-256:\s*({sha256}[^\s,]+)""",
    """MD-5:\s*({md5}[^\s,]+)""",
  ]
}
```