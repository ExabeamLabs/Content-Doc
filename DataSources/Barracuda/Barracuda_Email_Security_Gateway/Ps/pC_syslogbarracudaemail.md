#### Parser Content
```Java
{
Name = syslog-barracuda-email
    Vendor = Barracuda
    Product = Barracuda Email Security Gateway
    Lms = Syslog
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """scan: """, """ SCAN """ ]
    Fields = [
      """\Wscan:\s{1,100}(?:-|({host}[\w\-\.]{1,2000}))\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:-|({alert_id}[^\s]{1,2000})\-\S+)\s{1,100}({time}\d{1,100})\s{1,100}\d{1,100}\s{1,100}SCAN\s{1,100}\S+\s{1,100}(?:-|({sender}[^@]{1,2000}@({external_domain_sender}[^\s>]{1,2000})))\s{1,100}(?:-|({recipient}[^@]{1,2000}@({external_domain_recipient}[^\s>]{1,2000})))\s{1,100}(?:-|({spam_score}\S+))\s{1,100}({outcome}\d{1,100})\s{1,100}(?:-|({failure_reason}[^\s]{1,2000}))\s{1,100}\S+\s{1,100}SZ:({bytes}\d{1,100})\s{1,100}SUBJ:(|({subject}.+?))\s{0,100}$"""
    ]
    DupFields = [ "external_domain_sender->external_domain", "sender->external_address", "sender->email_user" ]
  

}
```