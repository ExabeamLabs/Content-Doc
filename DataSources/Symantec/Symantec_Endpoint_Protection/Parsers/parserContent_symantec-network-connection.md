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
    """\d\d:\d\d:\d\d (({host}[\w-]{1,2000})\s{1,100})?SymantecServer: (({=host}[\w-]{1,2000}),)?({src_host}[^,]{1,2000}),Local Host IP:"""
    """Local Host IP:\s{0,100}({src_ip}[^,]{1,2000})""",
    """Local Port:\s{0,100}({src_port}\d{1,100})""",
    """Local Host MAC:\s{0,100}({src_mac}[^,\s]{1,2000})""",
    """Remote Host IP:\s{0,100}({dest_ip}[^,\s]{1,2000})""",
    """Remote Host Name:\s{0,100}({dest_host}[^,\s]{1,2000})""",
    """Remote Port:\s{0,100}({dest_port}\d{1,100})""",
    """Remote Host MAC:\s{0,100}({dest_mac}[^,\s]{1,2000})""",
    """({protocol}[^,\s]{1,2000}),({direction}Inbound|Outbound)""",
    """Begin:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """,\s{0,100}Application:\s{0,100}({process}({directory}[^,]{0,2000}?[\\\/]{1,2000})({process_name}[^,\\\/]{1,2000})),"""
    """User Name:\s{0,100}(SYSTEM|none|NETWORK|LOCAL|({user}[^\s,]{1,2000}))""",
    """Rule:\s{1,100}(?:|({rule}[^,]{1,2000})),""",
    """Domain Name:\s{0,100}({domain}[^\s,]{1,2000})""",
    """Action:\s{0,100}({action}[^\s,]{1,2000})""",
    """SHA-256:\s{0,100}({sha256}[^\s,]{1,2000})""",
    """MD-5:\s{0,100}({md5}[^\s,]{1,2000})""",
  ]
}
```