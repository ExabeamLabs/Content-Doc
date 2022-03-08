#### Parser Content
```Java
{
Name = o365-inbox-rules-forward-to-2
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""UpdateInboxRules"""" ,""""Forward""", """"ClientRequestId":""", """"MailboxGuid":""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"OriginatingServer":\s{0,100}"({host}[\w\-.]{1,2000})\s""",
    """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"ResultStatus":\s{0,100}"({outcome}[^"]{1,2000})"""",
    """"ClientIP":\s{0,100}"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"UserId":\s{0,100}"({user_email}[^@"]{1,2000}@({user_domain}[^"]{1,2000}))"""",
    """"ActionType(\\)?":(\\)?"({activity}[^"\\]{1,2000})(\\)?"""",
    """"Operation":\s{0,100}"({event_name}[^"]{1,2000})"""",
    """Forward[^\}\]]{1,2000}Recipients(\\)?":\[(\\)?({recipients}"({recipient}[^\\",;@]{1,2000}@({target_domain}[^\\",;@]{1,2000}))[^\]]{1,2000})\]""",
    """"Workload":\s{0,100}"({app}[^"]{1,2000})"""",
    """"ClientProcessName":\s{0,100}"({process}[^"]{1,2000})""""
  ]
  DupFields = [ "recipient->target" ]


}
```