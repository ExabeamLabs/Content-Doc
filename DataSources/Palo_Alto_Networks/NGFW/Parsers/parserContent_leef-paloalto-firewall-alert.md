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
    """\s({host}[\w\.-]+)\s{1,100}LEEF:""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d \w+)\|""",
    """\|Type=({log_type}\w+)\|""",
    """LEEF:([^\|]*\|){2}({alert_name}[^\|]+)""",
    """\|cat=({alert_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName=({rule}[^\|][^\|]+)""",
    """\|usrName=(|((({domain}[^\|\\]+)\\)?({user}[^\|\\]+)))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]+)\\)?({src_user}[^\|\\]+)))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]+)\\)?({dest_user}[^\|\\]+)))\|""",
    """\|Application=({network_app}[^\|]+)""",
    """\|SourceZone=({src_network_zone}[^\|]+)""",
    """\|DestinationZone=({dest_network_zone}[^\|]+)""",
    """\|LogForwardingProfile=({profile}[^\|]+)""",
    """\|srcPort=(0|({src_port}\d{1,100}))\|""",
    """\|dstPort=(0|({dest_port}\d{1,100}))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d{1,100}))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d{1,100}))\|""",
    """\|proto=({protocol}[^\|]+)""",
    """\|srcBytes=({bytes_out}[\d.]+)\|""",
    """\|dstBytes=({bytes_in}[\d.]+)\|""",
    """\|Miscellaneous="(|({miscellaneous}[^=]+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]+)""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}[^\|]*)\|""",
    """\|Severity=({alert_severity}[^\|]+)\|""",
    """\|Direction=({direction}[\w-]+)\|""",
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