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
    """\|FireEye\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}.+?)\|({alert_severity}.+?)\|""",
    """\|FireEye\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}.+?)\|""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """\sshost=({src_host}[^\s]{1,2000})""",
    """\sfilePath=(?:({malware_url}[^\s.]{1,2000}\.[^\/\s]{1,2000}\/.+?)|({malware_file_name}.+?))\s\w+=""",
             """\scs1Label=sname cs1=({alert_name}[^\s]{1,2000})""",
    """\scs5Label=cncHost cs5=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]{1,2000}))""",
    """\srequest=({malware_url}[^\s]{1,2000})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """\sdhost=({dest_host}\S+)""",
    """\sduser=({user}[^@]{1,2000})(@[^\s]{1,2000})?\s{1,100}cn1Label""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```