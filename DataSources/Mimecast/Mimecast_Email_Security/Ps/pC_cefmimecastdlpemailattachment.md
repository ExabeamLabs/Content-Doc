#### Parser Content
```Java
{
Name = cef-mimecast-dlp-email-attachment
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName=Mimecast Email Security""", """"AttNames":""", """"aCode":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w.\-]{1,2000} Skyformation""",
    """"AttNames":\[({attachments}[^\]]{1,2000})\]""",
    """"aCode":"(|({alert_id}[^"]{1,2000}?))"""",
    """"acc":"({user}[^"]{1,2000})"""",
    """"MsgSize":"{0,20}({bytes}\d{1,100})""",
    """"Subject":"({subject}[^"]{1,2000})""",
    """"Sender":"(<>|({sender}[^"]{1,2000}))""",
    """"datetime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}-\d{1,100})""",
    """"AttCnt":({attachment_count}\d{1,100})""",
    """"AttSize":({attachment_size}\d{1,100})""",
    """"Hld":"({outcome}[^"]{1,2000})"""
  ]
}
```