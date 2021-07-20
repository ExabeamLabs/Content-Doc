#### Parser Content
```Java
{
Name = syslog-mcafee-epo-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Syslog
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"analyzername":"Data Loss Prevention"""",""""threatname":""" ]
    Fields = [
      """"detectedutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
      """"db_ip":"({dest_ip}[^"]{1,2000})""",
      """"threatname":"({alert_name}[^"]{1,2000}?)"""",
      """"analyzername":"({alert_type}[^"]{1,2000}?)"""",
      """"db_name":"({dest_host}[^"]{1,2000}?)"""",
      """"sourcehostname":"({src_host}[^"]{1,2000}?)"""",
      """"sourceprocessname":"({process}(({process_directory}[^"]{0,2000}?)\\)?({process_name}[^"\\]{0,2000}?))"""",
      """"threatactiontaken":"({outcome}[^"]{1,2000}?)"""",
      """"sourceusername":"(({domain}[^"\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^"]{1,2000})""""
    ]
    DupFields = [ "src_host->host" ]
  }
```