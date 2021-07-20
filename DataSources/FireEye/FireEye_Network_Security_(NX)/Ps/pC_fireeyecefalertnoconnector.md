#### Parser Content
```Java
{
Name = fireeye-cef-alert-no-connector
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""","""|FireEye|""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """rt=({time}[a-zA-Z]{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """externalId=({alert_id}\d{1,100})""",
    """\|FireEye\|([^\|]{1,2000}\|){3}({alert_type}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """\|FireEye\|([^\|]{1,2000}\|){3}({alert_name}[^\|]{1,2000})\|""",
    """\ssrc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({dest_host}[^\s]{1,2000})""",
    """\sfilePath=(?:({malware_url}[^\s.]{1,2000}\.[^\/\s]{1,2000}\/[^=]{1,2000}?)|({malware_file_name}[^=]{1,2000}?))\s\w+=""",
    """\scs1Label=sname cs1=({alert_name}[^\s]{1,2000})""",
    """\scs5Label=cncHost cs5=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]{1,2000}))""",
    """\srequest=({malware_url}[^\s]{1,2000})""",
    """\sdst=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({src_host}\S+)""",
    """\sduser=({user}[^@]{1,2000})(@[^\s]{1,2000})?\s{1,100}cn1Label""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sact=({action}[^=]{1,2000}?)\s{1,100}\w+="""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```