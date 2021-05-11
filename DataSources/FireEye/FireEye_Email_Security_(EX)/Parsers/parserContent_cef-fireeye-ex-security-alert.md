#### Parser Content
```Java
{
Name = cef-fireeye-ex-security-alert
  Vendor = FireEye
  Product = FireEye Email Security (EX)
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|FireEye|""", """flexString2Label=subject""", """|CMS|""", """fileType=""" ]
  Fields = [
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """rt=({time}[a-zA-Z]{3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
     """act=({action}[^=]+?)\s{0,100}\w+=""",
     """externalId=({alert_id}\d{1,100})""",
     """\|FireEye\|([^\|]+\|){3}({alert_name}[^\|]+)\|""",
     """\scs1Label=sname cs1=({alert_name}[^\s]+)""",
     """\|FireEye\|([^\|]+\|){3}({alert_type}[^\|]+)\|({alert_severity}[^\|]+)\|""",
     """\sdhost=({dest_host}\S+)""",
     """\scs5Label=cncHost cs5=(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))""",
     """\sdst=({dest_ip}[A-Fa-f:\d.]+)""",
     """\sfname=(?:[^,]+,)?\s{0,100}({file_name}.+?)\s{0,100}(?:\w+=|$)""",
     """\sdvc=({host}[A-Fa-f:\d.]+)""",
     """\sdvchost=({host}[^\s]+)""",
     """\ssrc=({src_ip}[A-Fa-f:\d.]+)""",
     """\sduser=({user}[^@]+)(@[^\s]+)?\s{1,100}cn1Label""",
     """\sduser=({user_email}[^@\s]+@[^,\s]+)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_file_name->malwareAttackerFile", "malware_url->malwareAttackerUrl", "dest_ip->malwareAttackerIp"]
    NameTemplate = """FireEye Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```