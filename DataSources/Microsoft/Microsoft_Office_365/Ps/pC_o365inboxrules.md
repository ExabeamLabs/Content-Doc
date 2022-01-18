#### Parser Content
```Java
{
Name = o365-inbox-rules
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Operation":"Set-Mailbox""" , """DeliverToMailboxAndForward""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """Forward.+?Value":"(smtp:)?({target}[^"]{1,2000}@({target_domain}[^"]{1,2000}))""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"\[?({src_ip}((\d{1,3}\.){1,3}\d{1,3}|[a-fA-F\d]{1,2000}:[A-Fa-f\d:]{1,2000}))\]?(:({src_port}\d{1,100}))?"""",
    """({activity}DeliverToMailboxAndForward)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """"Value":"(smtp:)?.+?@({target_domain}[^"]{1,2000})"""",
    """UserId":"({user_email}[^"\\\s@]{1,2000}@({user_domain}[^"\\\s@]{1,2000}))""",
    """({app}Office 365)"""
    """destinationServiceName =({app}.+?)\sdevice"""
  ]
  DupFields = ["user_domain->email_domain"]


}
```