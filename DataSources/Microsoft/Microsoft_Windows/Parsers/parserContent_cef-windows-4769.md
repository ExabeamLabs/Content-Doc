#### Parser Content
```Java
{
Name = cef-windows-4769
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-4769"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """"eventID":"4769"""", """A Kerberos service ticket was requested""" ]
  Fields = [
    """"systemTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]+?)\s{0,100}"""",
    """"targetSid":"({user_sid}[^"\s]+?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s@]+?)\s{0,100}"""",
    """"targetUserName":"({user_email}[^"\s@]+@[^"\s@]+?)\s{0,100}"""",
    """"targetDomainName":"({domain}[^"\s]+?)\s{0,100}"""",
    """"serviceName":"({service_name}[^"\s]+?)\s{0,100}"""",
    """"serviceName":"({dest_host}[^"\s]+?\$)\s{0,100}"""",
    """"ticketEncryptionType":"({ticket_encryption_type}[^"\s]+?)\s{0,100}"""",
    """"ticketOptions":"({ticket_options}[^"\s]+?)\s{0,100}"""",
    """"status":"({result_code}[^"]+?)\s{0,100}"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"ipPort":"({src_port}\d{1,100})""",
  ]
}
```