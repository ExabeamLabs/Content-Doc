#### Parser Content
```Java
{
Name = o365-phishing-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [""""Verdict":"Phish"""", """"Operation":"TIMailData"""", """"InternetMessageId":"""", """"Subject":""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """({alert_type}Phish)""",
    """"DetectionMethod":"({alert_name}[^"]{1,2000})"""",
    """"Recipients":\["({user_email}[^,;@]{1,2000}@([^;,"]{1,2000}))""",
    """"Id":"({alert_id}[^"]{1,2000})"""",
    """"SenderIp":"(0.0.0.0|({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?)))"""",
    """"SHA256":"({md5}[^"]{1,2000})"""",
    """"Verdict":"({verdict}[^"]{1,2000})"""",
    """"Subject":"\s{0,100}({additional_info}[^,"]{1,2000}?)(\s\t){0,100}"(,|$)"""",
    """"Directionality":"({direction}[^",]{1,2000})"""",
    """"P2Sender":"({sender}[^@",]{1,2000}@[^",]{1,2000})"""",
    """"P1Sender":"({sender}[^@",]{1,2000}@[^",]{1,2000})""""
  ] 
 DupFields = [ "user_email->recipient", "additional_info->subject" ]


}
```