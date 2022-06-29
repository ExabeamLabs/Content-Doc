#### Parser Content
```Java
{
Name = pan-cef-alert-7
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zzz"
  Conditions = [ """Palo Alto Networks|PAN-OS|""","""Windows Local Security Architect lsardelete access(30857)|THREAT|""" ]

pan-cef-alert = {
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [ """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\|Palo Alto Networks\|PAN-OS\|.*?\|({alert_type}.+?)\|THREAT\|""",
    """\|Palo Alto Networks\|PAN-OS\|.*?\|({alert_name}.+?)\|THREAT\|""",
    """\|Palo Alto Networks\|PAN-OS\|.*?\|[^|]{1,2000}?\|THREAT\|(Unknown|({alert_severity}.+?))\|""",
    """\scat=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """proto=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """app=(|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """act=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """flexString2=({additional_info}[^\s]{1,2000})""",
    """cs1=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """externalId=({alert_id}[^\s]{1,2000})""",
    """rt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """\srt=({time}\d{1,100})""",
    """src=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dst=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """duser=(({domain}[^\\=]{1,2000})\\+)?({user}[^\s@]{1,2000})(@({=domain}[^\s@=]{1,2000}))?""",
    """suser=(({domain}[^\\=]{1,2000})\\+)?({user}[^\s@]{1,2000})(@({=domain}[^\s@=]{1,2000}))?""",
    """sourceTranslatedAddress=(0.0.0.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """destinationTranslatedAddress=(0.0.0.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """dvchost=({host}[^\s]{1,2000})""",
    """request="({malware_url}.+?)"\s""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})""",
  ]
  DupFields = [ "alert_type->category" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address"]},
      {EntityType="device", Name ="dest_address", Fields=["dest_ip->ip_address"]},
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]}
    
}
```