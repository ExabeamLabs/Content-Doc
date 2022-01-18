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
    """"computer":"({host}[\w\-.]{1,2000})""",
    """"message":"({event_name}[^"]{1,2000}?)\s{0,100}"""",
    """"eventID":"({event_code}\d{1,100})""",
    """"eventRecordID":"({record_id}\d{1,100})""",
    """"severityValue":"({outcome}[^"]{1,2000}?)\s{0,100}"""",
    """"targetSid":"({user_sid}[^"\s]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user}[^"\s@]{1,2000}?)\s{0,100}"""",
    """"targetUserName":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000}?)\s{0,100}"""",
    """"targetDomainName":"({domain}[^"\s]{1,2000}?)\s{0,100}"""",
    """"serviceName":"({service_name}[^"\s]{1,2000}?)\s{0,100}"""",
    """"serviceName":"({dest_host}[^"\s]{1,2000}?\$)\s{0,100}"""",
    """"ticketEncryptionType":"({ticket_encryption_type}[^"\s]{1,2000}?)\s{0,100}"""",
    """"ticketOptions":"({ticket_options}[^"\s]{1,2000}?)\s{0,100}"""",
    """"status":"({result_code}[^"]{1,2000}?)\s{0,100}"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"ipPort":"({src_port}\d{1,100})""",
  ]


}
```