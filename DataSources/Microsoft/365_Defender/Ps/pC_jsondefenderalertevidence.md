#### Parser Content
```Java
{
Name = json-defender-alert-evidence
  Vendor = Microsoft
  Product = 365 Defender
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:SS"
  Conditions = [ """"category":"AdvancedHunting-AlertEvidence"""", """"operationName":"Publish"""", """"EntityType":""" ]
  Fields = [
    """"Timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"hostname":"({host}[^"]{1,2000})"""",
    """"AlertId":"({alert_id}[^"]{1,2000})"""",
    """"EntityType":"({entity_type}[^"]{1,2000})""",
    """"FileName":"({file_name}[^"]{1,2000})""",
    """"FolderPath":"({file_path}[^"]{1,2000})""",
    """"DeviceName":"({src_host}[^"]{1,2000})""",
    """"SHA256":"({sha256}[^"]{1,2000})""",
    """"SHA1":"({file_hash}[^"]{1,2000})""",
    """"DetectionStatus\\?":\\?"({outcome}[^"\\]{1,2000})""",
    """"AccountName":"(ALL|({user}[^"\s,]{1,2000}))"""",
    """"AccountUpn":"({user_email}[^"]{1,2000})""",
    """"AccountSid":"({user_sid}[^"]{1,2000})""",
    """"EmailSubject":"({subject}[^"]{1,2000})""",
    """"Recipient\\?":\\?"({recipient}[^"\\,]{1,2000})""",
    """"Sender\\?":\\?"({sender}[^"\\,]{1,2000})""",
    """"SenderIP\\?":\\?"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"RemoteIP\\?":\\?"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"Application\\?":\\?"({app}[^\\"]{1,2000})""",
    """"Urls\\?":\[\\?"({malware_url}[^\s,"]{1,2000})""",
    """"ProcessCommandLine":"({command_line}[^\n]{1,2000}?)","""
  ]


}
```