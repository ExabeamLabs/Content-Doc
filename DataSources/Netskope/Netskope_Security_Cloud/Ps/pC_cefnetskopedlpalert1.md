#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert-1
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"DLP"""", """destinationServiceName =Netskope""", """"alert_name":""""  ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"app":"({app}[^"]{1,2000})""",
    """"_id":"({alert_id}[^"]{1,2000})""",
    """"category":"({threat_category}[^"]{1,2000})""",
    """"md5":"({md5}[^"\s]{1,2000})"""",
    """"dlp_rule_severity":"({alert_severity}[^"]{1,2000})""",
    """"alert_type":"({alert_type}[^"]{1,2000})""",
    """"policy":"({additional_info}[^"]{1,2000})""",
    """"action":"({outcome}[^"]{1,2000})""",
    """"{0,20}hostname"{0,20}:"{0,20}({src_host}[^"]{1,2000})"""",
    """"from_user":"({from_user_at}[^"]{1,2000})"""",
    """"shared_with":"("shared_with_at}[^"]{1,2000})"""",
    """"sha256":"({sha256_at}[^"]{1,2000})"""",
    """"site":"({site_at}[^"]{1,2000})""""
  ]

cef-netskope-alert = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """"hostname":"({host}[^",]{1,2000})"""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"alert_name":"({alert_name}[^"]{1,2000})""",
    """"url":"({malware_url}[^"]{1,2000})""",
    """"userip":"({src_ip}[A-Fa-f:\d.]{1,2000})"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "alert_type->description", "malware_url->malwareAttackerUrl"]
    NameTemplate = """Netskope Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]},
      {EntityType="user", Name ="windows_id", Fields=["user->windows_id"]},
    
}
```