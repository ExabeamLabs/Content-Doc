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
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\.-]+)\s""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),Local:\s{0,100}(?:0+|({dest_host}[^,]+)),([^,]*,){3}Inbound,([^,]*,){9}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]+),Remote:\s{0,100}(?:0+|({src_host}[^,]+)),Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]+),Local:\s{0,100}(?:0+|({src_host}[^,]+)),([^,]*,){3}Outbound,""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),Remote:\s{0,100}(?:0+|({dest_host}[^,]+)),Outbound,([^,]*,){10}Remote Port ({dest_port}\d{1,100}),""",
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),Local:\s{0,100}(?:0+|({dest_host}[^,]+)),([^,]*,){3}Unknown,([^,]*,){9}Local Port ({dest_port}\d{1,100}),""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]+),Remote:\s{0,100}(?:0+|({src_host}[^,]+)),([^,]*,){3}Unknown,""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User:\s{0,100}(?:none|({user}[^,]+)),""",
    """Domain:\s{0,100}({domain}[^,\s]+),""",
    """MD-5: [^,]*,"{0,20}({additional_info}.+?)(\s{1,100}|"{1,20}),Local:""",
    """Domain\s{0,100}(Name)?:\s{0,100}({domain}[^,\s]+),""",
    """User\s{0,100}(Name)?:\s{0,100}(?:none|({user}[^,]+)),""",
    """(Inbound|Outbound|Unknown),({protocol}\w+),"""
    """Remote Host Name:\s{0,100}({dest_host}[^\s,]+)""",
    """Remote Host IP:\s{0,100}({dest_ip}[A-Fa-f.\d:]+)""",
    """Remote Host MAC:\s{0,100}({dest_mac}[^\s,]+)""",
    """Local Host IP:\s{0,100}({src_ip}[A-Fa-f.\d:]+)""",
    """Local Port:\s{0,100}({src_port}\d{1,100})""",
    """Remote Port:\s{0,100}({dest_port}\d{1,100})""",
    """({outcome}block)""",
    """({direction}Inbound|Outbound)""",
    """Event Description:\s{1,100}({additional_info}[^,]+?)\s{0,100}
```