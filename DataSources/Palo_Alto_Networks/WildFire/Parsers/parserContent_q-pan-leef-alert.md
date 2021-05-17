#### Parser Content
```Java
{
Name = q-pan-leef-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss" 
  Conditions = ["LEEF:1.0|Palo Alto Networks", "cat=THREAT|subtype=wildfire" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_endTime=({time}\d{13})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\s({host}[\w\.-]{1,2000})\s{1,100}LEEF:""",
    """subtype=({alert_type}wildfire)""",
    """Severity=({alert_severity}\d{1,100})""",
    """Severity=({alert_severity}[^\|]{1,2000})\|""",
    """(URLCategory|Severity)=({alert_severity}benign|informational)""",
    """usrName=(({domain}[^\\]{1,2000})\\)?(|({user}[^\|]{1,2000}))\|(SerialNumber|SourceUser)""",
    """DestinationUser=(?:[^\\/]{1,2000}[\\/])?({user}[^|]{1,2000})\|Application=""",
    """\|src=({src_ip}[^|]{1,2000})\|dst=({dest_ip}[^|]{1,2000})\|""",
    """SessionID=({alert_id}[^|]{1,2000})\|""",
    """LEEF[^|]{1,2000}?\|([^\|]{1,2000}\|){3}({alert_name}[^|]{1,2000})\|""",
    """\|URLCategory=({category}[^\|]{0,2000})\|""",
    """\|Miscellaneous="?({miscellaneous}[^\|"]{1,2000})"?\|"""
  ]
  DupFields = [ "miscellaneous->malware_url" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "category->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```