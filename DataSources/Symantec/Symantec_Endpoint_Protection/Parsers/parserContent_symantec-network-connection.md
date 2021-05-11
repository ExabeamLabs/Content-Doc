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
    """\d\d:\d\d:\d\d (({host}[\w-]+)\s{1,100})?SymantecServer: (({=host}[\w-]+),)?({src_host}[^,]+),Local Host IP:"""
    """Local Host IP:\s{0,100}({src_ip}[^,]+)""",
    """Local Port:\s{0,100}({src_port}\d{1,100})""",
    """Local Host MAC:\s{0,100}({src_mac}[^,\s]+)""",
    """Remote Host IP:\s{0,100}({dest_ip}[^,\s]+)""",
    """Remote Host Name:\s{0,100}({dest_host}[^,\s]+)""",
    """Remote Port:\s{0,100}({dest_port}\d{1,100})""",
    """Remote Host MAC:\s{0,100}({dest_mac}[^,\s]+)""",
    """({protocol}[^,\s]+),({direction}Inbound|Outbound)""",
    """Begin:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,\s{0,100}Application:\s{0,100}({process}({directory}[^,]*?[\\\/]+)({process_name}[^,\\\/]+)),"""
    """User Name:\s{0,100}(SYSTEM|none|NETWORK|LOCAL|({user}[^\s,]+))""",
    """Rule:\s{1,100}(?:|({rule}[^,]+)),""",
    """Domain Name:\s{0,100}({domain}[^\s,]+)""",
    """Action:\s{0,100}({action}[^\s,]+)""",
    """SHA-256:\s{0,100}({sha256}[^\s,]+)""",
    """MD-5:\s{0,100}({md5}[^\s,]+)""",
  ]
}
```