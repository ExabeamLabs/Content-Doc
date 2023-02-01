#### Parser Content
```Java
{
Name = barracuda-dlp-email-alert-out
    Vendor = Barracuda
    Product = Barracuda Email Security Gateway
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-dd-MM'T'HH:mm:ss"
    Conditions = [ """"action":"allowed"""", """"delivered":"delivered"""", """"hdr_from":"""", """"hdr_to":"""", """Queued mail for delivery""" ]
    Fields = [
    """({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})Z\s({host}[\w\-.]{1,2000})\s"""
    """"action":"({action}[^"]{1,100})""""
    """"src_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
    """"delivered":"({outcome}[^"]{1,2000})""""
    """"email":"({recipient}[^@"]{1,2000}@[^"]{1,2000})"""
    """"env_from":"({sender}[^@"]{1,2000}@[^"]{1,2000})"""
    """"subject":"({subject}[^"]{1,2000}?)\s{0,20}""""
    """"size":({bytes}\d{1,20}),"""
    """"message_id":"({message_id}[^"]{1,2000})""""
    ]


}
```