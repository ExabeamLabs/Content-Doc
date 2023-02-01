#### Parser Content
```Java
{
Name = barracuda-dlp-email-alert-out-failed
    Vendor = Barracuda
    Product = Barracuda Email Security Gateway
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """"action":"blocked""", """"delivered":"rejected""", """reason":""" ]
    Fields = [
    """({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})Z\s({host}[\w\-.]{1,2000})\s"""
    """"action":"({action}[^"]{1,100})""""
    """"src_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
    """"delivered":"({outcome}[^"]{1,2000})""""
    """"email":"({recipient}[^@"]{1,2000}@[^"]{1,2000})"""
    """"env_from":"({sender}[^@"]{1,2000}@[^"]{1,2000})"""
    """"subject":"({subject}[^"]{1,2000}?)\s{0,20}""""
    """"size":({bytes}\d{1,20}),"""
    """"reason":"({failure_reason}[^"]{1,2000})"""
    """"message_id":"({message_id}[^"]{1,2000})""""
    ]


}
```