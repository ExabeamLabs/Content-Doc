#### Parser Content
```Java
{
Name = leef-paloalto-firewall-drop
  Conditions = [ """LEEF:""", """|Palo Alto Networks|PAN-OS Syslog Integration|""", """|Type=TRAFFIC|Subtype=drop|""" ]

leef-paloalto-firewall = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Fields = [
    """\s({host}[\w\.-]{1,2000})(\s{1,100}|,"{1,100})LEEF:""",
    """\|DeviceName =({host}[^\|"]{1,2000}?)\s{0,100}(\||"*$)""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)\|""",
    """\|Type=({log_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName =({rule}[^\|].*?)\|""",
    """\|usrName =(|((({domain}[^\|\\]{1,2000})\\)?({user}[^\|\\]{1,2000})))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]{1,2000})\\)?({src_user}[^\|\\]{1,2000})))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]{1,2000})\\)?({dest_user}[^\|\\]{1,2000})))\|""",
    """\|Application=((?i)not-applicable|({network_app}[^\|]{1,2000}?))\|""",
    """\|SourceZone=({src_network_zone}[^\|]{1,2000}?)\|""",
    """\|DestinationZone=({dest_network_zone}[^\|]{1,2000}?)\|""",
    """\|LogForwardingProfile=({profile}[^\|]{1,2000}?)\|""",
    """\|srcPort=(0|({src_port}\d{1,100}))\|""",
    """\|dstPort=(0|({dest_port}\d{1,100}))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d{1,100}))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d{1,100}))\|""",
    """\|proto=({protocol}[^\|"]{1,2000}?)\|""",
    """\|totalBytes=({bytes}[\d.]{1,2000})\|""",
    """\|srcBytes=({bytes_out}[\d.]{1,2000})\|""",
    """\|dstBytes=({bytes_in}[\d.]{1,2000})\|""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]{0,2000})\|""",
    """\|Severity=({severity}informational)\|""",
    """\|Direction=({direction}[\w-]{1,2000})\|""",
    """\|sequence=({sequence}\d{1,100})\|""",
    """\|SessionEndReason=({outcome}[^\|"]{1,2000}?)\|""",
    """\|action=({action}\w+)\|""",
  
}
```