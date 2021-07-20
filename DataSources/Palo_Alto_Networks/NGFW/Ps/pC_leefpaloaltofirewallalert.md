#### Parser Content
```Java
{
Name = leef-paloalto-firewall-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = ["""LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""|action=alert|"""]
  Fields = [
    """\s({host}[\w\.-]{1,2000})\s{1,100}LEEF:""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)\|""",
    """\|Type=({log_type}\w+)\|""",
    """LEEF:([^\|]{0,2000}\|){2}({alert_name}[^\|]{1,2000})""",
    """\|cat=({alert_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName=({rule}[^\|][^\|]{1,2000})""",
    """\|usrName=(|((({domain}[^\|\\]{1,2000})\\)?({user}[^\|\\]{1,2000})))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]{1,2000})\\)?({src_user}[^\|\\]{1,2000})))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]{1,2000})\\)?({dest_user}[^\|\\]{1,2000})))\|""",
    """\|Application=({network_app}[^\|]{1,2000})""",
    """\|SourceZone=({src_network_zone}[^\|]{1,2000})""",
    """\|DestinationZone=({dest_network_zone}[^\|]{1,2000})""",
    """\|LogForwardingProfile=({profile}[^\|]{1,2000})""",
    """\|srcPort=(0|({src_port}\d{1,100}))\|""",
    """\|dstPort=(0|({dest_port}\d{1,100}))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d{1,100}))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d{1,100}))\|""",
    """\|proto=({protocol}[^\|]{1,2000})""",
    """\|srcBytes=({bytes_out}[\d.]{1,2000})\|""",
    """\|dstBytes=({bytes_in}[\d.]{1,2000})\|""",
    """\|Miscellaneous="(|({miscellaneous}[^=]{1,2000}?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]{1,2000})""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]{0,2000})\|""",
    """\|Severity=({alert_severity}[^\|]{1,2000})\|""",
    """\|Direction=({direction}[\w-]{1,2000})\|""",
    """\|sequence=({sequence}\d{1,100})\|""",
    """\|action=({action}\w+)\|""",
 ]
 DupFields = [ "miscellaneous->malware_url" ]
 SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "category->malwareCategory", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```