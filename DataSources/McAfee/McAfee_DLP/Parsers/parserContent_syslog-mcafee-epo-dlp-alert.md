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
      """"detectedutc":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
      """"db_ip":"({dest_ip}[^"]+)""",
      """"threatname":"({alert_name}[^"]+?)"""",
      """"analyzername":"({alert_type}[^"]+?)"""",
      """"db_name":"({dest_host}[^"]+?)"""",
      """"sourcehostname":"({src_host}[^"]+?)"""",
      """"sourceprocessname":"({process}(({process_directory}[^"]*?)\\)?({process_name}[^"\\]*?))"""",
      """"threatactiontaken":"({outcome}[^"]+?)"""",
      """"sourceusername":"(({domain}[^"\\\/]+?)[\\\/]+)?({user}[^"]+)""""
    ]
    DupFields = [ "src_host->host" ]
  }
```