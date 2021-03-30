#### Parser Content
```Java
{
Name = cef-palo-alto-networks-setip
  DataType = "vpn-set-ip"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|client switch to SSL tunnel mode succeeded|""" ]
  Fields = ${PaloAltoParserTemplates.cef-palo-alto-networks-firewall.Fields}[
    """Private IP:\s*({src_translated_ip}[a-fA-F\d.:]+[^\.\s])""",
  ]
}
cef-palo-alto-networks-firewall = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """\sdvchost=({host}.+?)\s+(\w+=|$)""",
    """\Wrt=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+\w+)""",
    """\srt=({time}\d+)\s+(\w+=|$)""",
    """\sduser=(?=[^\s]+@[^\s]+)({user}[^\s@]+)@({domain}[^\s@]+)\s+(\w+=|$)""",
    """\sduser=(?!\S+@\S+)(({domain}[^\\\s]+)?\\+)?(|({user}[^\\\s]+))\s+(\w+=|$)""",
    """\ssuser=(?=[^\s]+@[^\s]+)({user}[^\s@]+)@({domain}[^\s@]+)\s+(\w+=|$)""",
    """\ssuser=(?!\S+@\S+)(({domain}[^\\\s]+)?\\+)?(|({user}[^\\\s]+))\s+(\w+=|$)""",
    """({log_type}TRAFFIC)""",
    """\|({subtype}[^\|]+)\|TRAFFIC""",
    """\scs1=({rule}.+?)\s+(\w+=|$)""",
    """\sshost=({src_host}.+?)\s+(\w+=|$)""",
    """\sdhost=({dest_host}.+?)\s+(\w+=|$)""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s+(\w+=|$)""",
    """\sdst=(0.0.0.0|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s+(\w+=|$)""",
    """\ssourceTranslatedAddress=(0.0.0.0|({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s+(\w+=|$)""",
    """\sdestinationTranslatedAddress=(0.0.0.0|({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s+(\w+=|$)""",
    """\sspt=(0|({src_port}\d+))\s+(\w+=|$)""",
    """\sdpt=(0|({dest_port}\d+))\s+(\w+=|$)""",
    """\ssourceTranslatedPort=(0|({src_translated_port}\d+))\s+(\w+=|$)""",
    """\sdestinationTranslatedPort=(0|({dest_translated_port}\d+))\s+(\w+=|$)""",
    """\sapp=({network_app}.+?)\s+(\w+=|$)""",
    """\scs4=({src_network_zone}.+?)\s+(\w+=|$)""",
    """\scs5=({dest_network_zone}.+?)\s+(\w+=|$)""",
    """\scs6=({profile}.+?)\s+(\w+=|$)""",
    """\sproto=({protocol}.+?)\s+(\w+=|$)""",
    """\sin=({bytes_in}[\d.]+)\s+(\w+=|$)""",
    """\sout=({bytes_out}[\d.]+)\s+(\w+=|$)""",
    """\scs2=({category}.+?)\s+(\w+=|$)""",
    """\sseverity=({severity}.+?)\s+(\w+=|$)""",
    """\sdeviceDirection=({direction}.+?)\s+(\w+=|$)""",
    """\scategoryOutcome=\/?({outcome}.+?)\s+(\w+=|$)""",
    """\sreason=(?:n\/a|({reason}.+?))\s+(\w+=|$)""",
  ]

```