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
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s""",
    """SymantecServer:\s*({src_host}[^,]+?)\s*(,|$)"""
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

${SymantecParserTemplates.symantec-critical-sys-protection}{
  Name = symantec-account-switch-failed
  DataType = "account-switch"
  Conditions = [ """SVA_IP_ADDRESS: """, """ USER_NAME:""", """failed SU to """ ]
  Fields = ${SymantecParserTemplates.symantec-critical-sys-protection.Fields} [
    """To Username:\s*({account}[^"\s]+)""",
    """({outcome}(F|f)ailed)""",
    """Event source:\s*({process_name}[^"]+?)\s*From""",
    """({event_name}failed SU to [^"]+?)\s*Event"""
  ]
}
```