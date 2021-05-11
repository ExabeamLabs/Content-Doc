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
    """\s({host}[\w\.-]+)\s{1,100}LEEF:""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|Type=({log_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName=({rule}[^\|]*?)\|""",
    """\|usrName=(|((({domain}[^\|\\]+)\\)?({user}[^\|\\]+)))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]+)\\)?({src_user}[^\|\\]+)))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]+)\\)?({dest_user}[^\|\\]+)))\|""",
    """\|Application=({network_app}[^\|]*?)\|""",
    """\|SourceZone=({src_network_zone}[^\|]*?)\|""",
    """\|DestinationZone=({dest_network_zone}[^\|]*?)\|""",
    """\|LogForwardingProfile=({profile}[^\|]*?)\|""",
    """\|srcPort=(0|({src_port}\d{1,100}))\|""",
    """\|dstPort=(0|({dest_port}\d{1,100}))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d{1,100}))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d{1,100}))\|""",
    """\|proto=({protocol}[^\|]+)""",
    """\|totalBytes=({bytes}[\d.]+)\|""",
    """\|srcBytes=({bytes_out}[\d.]+)\|""",
    """\|dstBytes=({bytes_in}[\d.]+)\|""",
    """\|Miscellaneous="(|({miscellaneous}[^=]+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]+)""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]*)\|""",
    """\|Severity=({severity}informational)\|""",
    """\|Direction=({direction}[\w-]+)\|""",
    """\|sequence=({sequence}\d{1,100})\|""",
    """\|SessionEndReason=({outcome}[^\|]+)""",
    """\|action=({action}\w+)\|""",
    """\|SourceLocation=({src_location}[^\|]+)\|""",
  ]
}
```