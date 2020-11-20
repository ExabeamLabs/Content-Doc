#### Parser Content
```Java
{
Name = o365-phishing-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Verdict":"Phish""", """Operation":"TIMailData""", """InternetMessageId":"""", """Subject":""""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """({alert_type}Phish)""",
    """DetectionMethod":"({alert_name}[^"]+)"""",
    """Recipients":\["({user_email}[^,;@]+@([^;,"]+))""",
    """Id":"({alert_id}[^"]+)"""",
    """requestClientApplication=({process}.+?)\s*(\w+=|$)""",
    """FileName":"\s*({malware_url}[^"]+?)\s*"""",
    """SenderIp":"({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))"""",
    """SHA256":"({md5}[^"]+)"""",
    """UserId":"({additional_info}[^"]+)"""",
    """P2Sender":"({additional_info}[^"]+)"""",
    """"Verdict":"({verdict}[^"]+)""",
    """Subject":"\s*({additional_info}[^"]+?)\s*"""",
  ]
  DupFields = ["process->process_name"]
}
```