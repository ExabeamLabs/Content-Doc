#### Parser Content
```Java
{
Name = cef-netskope-alert-policy
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"alert":"yes"""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"timestamp":({time}\d+)""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """"userip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"malsite_category":\["({threat_category}[^"]+)"[^\]]*?\]""",
    """"alert_name":"({alert_name}[^"]+)""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"url":"({malware_url}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """"referer":"({referrer}[^"]+)""",
    """"policy":"({additional_info}[^"]+)""",
    """"page":"({web_domain}[^"]+)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Netskope Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```