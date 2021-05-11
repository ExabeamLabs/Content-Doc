#### Parser Content
```Java
{
Name = cef-windows-4768
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4768"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4768"""", """A Kerberos authentication ticket (TGT) was requested""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]+?)\s{0,100}"""",
    """"targetSid":"({user_sid}[^"\s]+?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s]+?)\s{0,100}"""",
    """"targetDomainName":"({domain}[^"\s]+?)\s{0,100}"""",
    """"status":"({result_code}[^"]+?)\s{0,100}"""",
    """"ipAddress":"({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """"ticketEncryptionType":"({ticket_encryption_type}[^"]+)""",
    """ticketOptions":"({ticket_options}[^"]+)""",
    """"serviceName":"({service_name}[^"]+)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```