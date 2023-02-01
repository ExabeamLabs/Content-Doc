#### Parser Content
```Java
{
Name = cef-forcepoint-dlp-email-alert-2
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Forcepoint|Forcepoint DLP|""", """violationTriggers="""", """CEF:""" ]
  Fields = [
    """eventTime="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """sourceHostname="({host}[\w\-.]{1,2000})"""",
    """application="({app}[^"]{1,2000})"""",
    """action="({outcome}[^"]{1,2000})"""",
    """direction="({direction}[^"]{1,2000})"""",
    """fileNames="(None|({attachments}({attachment}[^;"]{1,2000})[^"]{0,2000}))"""",
    """fileSize="({bytes}\d{1,100})"""",
    """incidentID="({alert_id}[^"]{1,2000})"""",
    """operationType="(None|({activity}[^"]{1,2000}))"""",
    """rules="({alert_type}[^"]{1,2000}?)\s{0,100}"""",
    """severity="({alert_severity}[^"]{1,2000})"""",
    """sourceEmail="({email_address}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""",
    """sourceIP="({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """sourceUsername="(({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """details="({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """policies="({alert_name}[^"]{1,2000}?)\s{0,100}"""",
  ]


}
```