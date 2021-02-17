#### Parser Content
```Java
{
Name = symantec-epp-network-alert-2
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature ID""", """traffic from IP address""", """block""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s+\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """Local:\s*({dest_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({dest_host}[^,]+)),([^,]*,){3}Inbound,([^,]*,){9}Local Port ({dest_port}\d+),""",
    """Remote:\s*({src_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({src_host}[^,]+)),Inbound,""",
    """Local:\s*({src_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({src_host}[^,]+)),([^,]*,){3}Outbound,""",
    """Remote:\s*({dest_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({dest_host}[^,]+)),Outbound,([^,]*,){10}Remote Port ({dest_port}\d+),""",
    """Local:\s*({dest_ip}[a-fA-F:\.\d]+),Local:\s*(?:0+|({dest_host}[^,]+)),([^,]*,){3}Unknown,([^,]*,){9}Local Port ({dest_port}\d+),""",
    """Remote:\s*({src_ip}[a-fA-F:\.\d]+),Remote:\s*(?:0+|({src_host}[^,]+)),([^,]*,){3}Unknown,""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),""",
    """Begin:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s*(?:none|({user}[^,]+)),""",
    """Domain:\s*({domain}[^,\s]+),""",
    """MD-5: [^,]*,"*({additional_info}.+?)(\s+|"+),Local:""",
    """Domain\s*(Name)?:\s*({domain}[^,\s]+),""",
    """User\s*(Name)?:\s*(?:none|({user}[^,]+)),""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),"""
    """Remote Host Name:\s*({dest_host}[^\s,]+)""",
    """Remote Host IP:\s*({dest_ip}[A-Fa-f.\d:]+)""",
    """Remote Host MAC:\s*({dest_mac}[^\s,]+)""",
    """Local Host IP:\s*({src_ip}[A-Fa-f.\d:]+)""",
    """Local Port:\s*({src_port}\d+)""",
    """Remote Port:\s*({dest_port}\d+)""",
    """({outcome}block)""",
    """({direction}Inbound|Outbound)""",
    """Event Description:\s+({additional_info}[^,]+?)\s*,Local""",
    """({activity}The client[^,]+?block traffic)""",
    """({activity}The traffic from IP address [^,]+? was blocked)""",
  ]
}
```