#### Parser Content
```Java
{
Name = leef-paloalto-firewall-allow
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = ["""LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""|allow|"""]
  Fields = [
    """\s({host}[\w\.-]+)\s+LEEF:""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """\|devTime=({time}\w{3}\s+\d+ \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|Type=({log_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName=({rule}[^\|].*?)\|""",
    """\|usrName=(|((({domain}[^\|\\]+)\\)?({user}[^\|\\]+)))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]+)\\)?({src_user}[^\|\\]+)))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]+)\\)?({dest_user}[^\|\\]+)))\|""",
    """\|Application=({network_app}[^\|].*?)\|""",
    """\|SourceZone=({src_network_zone}[^\|].*?)\|""",
    """\|DestinationZone=({dest_network_zone}[^\|].*?)\|""",
    """\|LogForwardingProfile=({profile}[^\|].*?)\|""",
    """\|srcPort=(0|({src_port}\d+))\|""",
    """\|dstPort=(0|({dest_port}\d+))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d+))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d+))\|""",
    """\|proto=({protocol}.*?)\|""",
    """\|totalBytes=({bytes}[\d.]+)\|""",
    """\|srcBytes=({bytes_out}[\d.]+)\|""",
    """\|dstBytes=({bytes_in}[\d.]+)\|""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s*$)""",
    """\|URLCategory=({category}.*?)\|""",
    """\|Severity=({severity}informational)\|""",
    """\|Direction=({direction}[\w-]+)\|""",
    """\|sequence=({sequence}\d+)\|""",
    """\|SessionEndReason=({outcome}.*?)\|""",
    """\|action=({action}\w+)\|""",
    """\|SourceLocation=({src_location}[^\|]+)\|""",
  ]
}
```