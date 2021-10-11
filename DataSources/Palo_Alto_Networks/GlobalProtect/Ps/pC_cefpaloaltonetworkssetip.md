#### Parser Content
```Java
{
Name = cef-palo-alto-networks-setip
  DataType = "vpn-set-ip"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|client switch to SSL tunnel mode succeeded|""" ]
  Fields = ${PaloAltoParserTemplates.cef-palo-alto-networks-firewall.Fields}[
    """Private IP:\s{0,100}({src_translated_ip}[a-fA-F\d.:]{1,2000}[^\.\s])""",
  ]
}
cef-palo-alto-networks-firewall = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """\sdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+)""",
    """\srt=({time}\d{1,100})\s{1,100}(\w+=|$)""",
    """\sduser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user}[^\s@]{1,2000})@({domain}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\sduser=(?!\S+@\S+)(({domain}[^\\\s]{1,2000})?\\+)?(|({user}[^\\\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\ssuser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user}[^\s@]{1,2000})@({domain}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssuser=(?!\S+@\S+)(({domain}[^\\\s]{1,2000})?\\+)?(|({user}[^\\\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """({log_type}TRAFFIC)""",
    """\|({subtype}[^\|]{1,2000})\|TRAFFIC""",
    """\scs1=({rule}.+?)\s{1,100}(\w+=|$)""",
    """\sshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
    """\sdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s{1,100}(\w+=|$)""",
    """\sdst=(0.0.0.0|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s{1,100}(\w+=|$)""",
    """\ssourceTranslatedAddress=(0.0.0.0|({src_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s{1,100}(\w+=|$)""",
    """\sdestinationTranslatedAddress=(0.0.0.0|({dest_translated_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}))\s{1,100}(\w+=|$)""",
    """\sspt=(0|({src_port}\d{1,100}))\s{1,100}(\w+=|$)""",
    """\sdpt=(0|({dest_port}\d{1,100}))\s{1,100}(\w+=|$)""",
    """\ssourceTranslatedPort=(0|({src_translated_port}\d{1,100}))\s{1,100}(\w+=|$)""",
    """\sdestinationTranslatedPort=(0|({dest_translated_port}\d{1,100}))\s{1,100}(\w+=|$)""",
    """\sapp=({network_app}.+?)\s{1,100}(\w+=|$)""",
    """\scs4=({src_network_zone}.+?)\s{1,100}(\w+=|$)""",
    """\scs5=({dest_network_zone}.+?)\s{1,100}(\w+=|$)""",
    """\scs6=({profile}.+?)\s{1,100}(\w+=|$)""",
    """\sproto=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\sin=({bytes_in}[\d.]{1,2000})\s{1,100}(\w+=|$)""",
    """\sout=({bytes_out}[\d.]{1,2000})\s{1,100}(\w+=|$)""",
    """\scs2=({category}.+?)\s{1,100}(\w+=|$)""",
    """\sseverity=({severity}.+?)\s{1,100}(\w+=|$)""",
    """\sdeviceDirection=({direction}.+?)\s{1,100}(\w+=|$)""",
    """\scategoryOutcome=\/?({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\sreason=(?:n\/a|({reason}.+?))\s{1,100}(\w+=|$)""",
  ]

```