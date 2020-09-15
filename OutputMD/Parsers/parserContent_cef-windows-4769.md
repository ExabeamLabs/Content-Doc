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
    """"systemTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"computer":"({host}[\w\-.]+)""",
    """"message":"({event_name}[^"]+?)\s*"""",
    """"eventID":"({event_code}\d+)""",
    """"eventRecordID":"({record_id}\d+)""",
    """"severityValue":"({outcome}[^"]+?)\s*"""",
    """"targetSid":"({user_sid}[^"\s]+?)\s*"""",
    """"targetUserName":"({user}[^"\s@]+?)\s*"""",
    """"targetUserName":"({user_email}[^"\s@]+@[^"\s@]+?)\s*"""",
    """"targetDomainName":"({domain}[^"\s]+?)\s*"""",
    """"serviceName":"({service_name}[^"\s]+?)\s*"""",
    """"serviceName":"({dest_host}[^"\s]+?\$)\s*"""",
    """"ticketEncryptionType":"({ticket_encryption_type}[^"\s]+?)\s*"""",
    """"ticketOptions":"({ticket_options}[^"\s]+?)\s*"""",
    """"status":"({result_code}[^"]+?)\s*"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)""",
    """"ipPort":"({src_port}\d+)""",
  ]
}
```