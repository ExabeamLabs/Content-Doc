#### Parser Content
```Java
{
Name = cef-palo-alto-networks-firewall-connection
  DataType = "network-connection"
  Conditions = [ """CEF:0|Palo Alto Networks|""", """|TRAFFIC|deny|""" ]
  Fields = ${PaloAltoParserTemplates.cef-palo-alto-network-event.Fields}[
   """({log_type}TRAFFIC)""",
  ]

cef-palo-alto-network-event = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """\sdvchost=({host}[\w.-]{1,2000}?)\s{1,100}(\w+=|$)""",
    """rt=({time}\w{3}\s\d{2}\s\d{4}\s(\d{2}:){2}\d{2})\s""",
    """\ssrc=(0.0.0.0|({src_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\sdst=(0.0.0.0|({dest_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\ssourceTranslatedAddress=(0.0.0.0|({src_translated_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\sdestinationTranslatedAddress=(0.0.0.0|({dest_translated_ip}[A-Fa-f\d.:]{1,2000}))\s{1,100}(\w+=|$)""",
    """\scs1=({rule}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\sduser=({user}[^\s@]{1,2000})@({domain}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\sduser=(({domain}[^\\\s]{1,2000})?\\+)?(|({user}[^\\\s@]{1,2000}))\s{1,100}(\w+=|$)""",
    """\ssuser=({user}[^\s@]{1,2000})@({domain}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssuser=(({domain}[^\\\s]{1,2000})?\\+)?(|({user}[^\\\s@]{1,2000}))\s{1,100}(\w+=|$)""", 
    """\sapp=({network_app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\scs4=({src_network_zone}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\scs5=({dest_network_zone}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\sspt=(0|({src_port}\d{1,5}))\s{1,100}(\w+=|$)""",
    """\sdpt=(0|({dest_port}\d{1,5}))\s{1,100}(\w+=|$)""",
    """\ssourceTranslatedPort=(0|({src_translated_port}\d{1,5}))\s{1,100}(\w+=|$)""",
    """\sdestinationTranslatedPort=(0|({dest_translated_port}\d{1,5}))\s{1,100}(\w+=|$)""",
    """\sproto=({protocol}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\sact=(|({outcome}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sin=({bytes_in}[\d]{1,2000})\s{1,100}(\w+=|$)""",
    """\sout=({bytes_out}[\d]{1,2000})\s{1,100}(\w+=|$)""",
    """externalId=({alert_id}[^\s]{1,2000})""",
    """\sreason=(?:n\/a|({reason}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\sPanOSThreatID="{0,20}({alert_name}[^"=\(]{1,2000}?)(\s{0,100}\([^\)]{1,1000}?\)?)"{0,20}\s{1,100}\w+=""",
   
}
```