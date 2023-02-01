#### Parser Content
```Java
{
Name = netskope-dlp-alert-2
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"alert_type":"DLP"""", """"alert":"yes"""", """"src-application-name":"Netskope"""", """"triggered-by":""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"app":"({app}[^"]{1,2000})"""",
    """"_id":"({alert_id}[^"]{1,2000})"""",
    """"category":"({threat_category}[^"]{1,2000})"""",
    """"md5":"({md5}[^"\s]{1,2000})"""",
    """"dlp_rule_severity":"({alert_severity}[^"]{1,2000})"""",
    """"alert_type":"({alert_name}[^"]{1,2000})"""",
    """"type":"({alert_type}[^"]{1,2000})"""",
    """"policy":"({additional_info}[^"]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"object":"({subject}[^"]{1,2000}?)\s{0,100}"""",
    """"file_size":({bytes}\d{1,20})""",
    """"mime_type":"({mime}[^"]{1,2000})""""
  ]

cef-netskope-alert = {
  Vendor = Netskope
  Product = Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """"hostname":"({host}[^",]{1,2000})"""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}\.[^"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
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