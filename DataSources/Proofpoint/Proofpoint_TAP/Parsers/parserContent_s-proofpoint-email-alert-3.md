#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-3
  Vendor = Proofpoint
  Product = Proofpoint TAP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ProofPointTAPMessagesBlocked""", """sender_s":""", """"senderIP_s":""", """recipient_s":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """threatTime\\*"{1,20}:\s{0,100}\\*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """spamScore_d"{1,20}:\s{0,100}"{1,20}({spam_score}\d{1,100})""",
    """phishScore_d"{1,20}:\s{0,100}"{1,20}({phishing_score}\d{1,100})""",
    """"malwareScore_d"{1,20}:\s{0,100}"{1,20}({malware_score}\d{1,100})""",
    """classification\\*"{1,20}:\s{0,100}\\*"{1,20}({alert_type}[^",]{1,2000}?)\\*\s{0,100}"""",
    """"subject_s"{1,20}:\s{0,100}"{1,20}({subject}[^",]{1,2000}?)\s{0,100}"""",
    """"fromAddress_s"{1,20}:\s{0,100}"{1,20}\[(\\r|\\n)*\s{0,100}\\"{1,20}({sender}[^",;]{1,2000}@[^",;]{1,2000}[^"]{0,2000})\\""",
    """"recipient_s"{1,20}:\s{0,100}"{1,20}\[(\\r|\\n)*\s{0,100}\\"{1,20}({recipient}[^",;]{1,2000}@[^",;]{1,2000}[^"]{0,2000})\\""",
    """GUID_s"{1,20}:\s{0,100}"{1,20}({alert_id}[^",]{1,2000}?)\s{0,100}"""",
    """senderIP_s"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"filename\\*"{1,20}:\s{0,100}\\*"{1,20}({attachments}(?!text)[^"\\]{1,2000})""",
    """"md5\\*"{1,20}:\s{0,100}\\*"{1,20}({md5}[^\\"]{1,2000})""",
    """"sha256\\*"{1,20}:\s{0,100}\\*"{1,20}({sha256}[^\\"]{1,2000})""",
    """"threatStatus\\*"{1,20}:\s{0,100}\\*"{1,20}({status}[^\\"]{1,2000})""",
    """"threatID\\*"{1,20}:\s{0,100}\\*"{1,20}({threat_id}[^\\"]{1,2000})""",
    """"threatUrl\\*"{1,20}:\s{0,100}\\*"{1,20}({malware_url}[^\\"]{1,2000})""",
    """"messageSize_d\\*"{1,20}:\s{0,100}\\*"{1,20}({bytes}\d{1,100})""",
    """"oContentType\\*"{1,20}:\s{0,100}\\*"{1,20}({mime}[^\\"]{1,2000})""",
    """"QID_s\\*"{1,20}:\s{0,100}\\*"{1,20}({query_id}[^\\"]{1,2000})""",
    """"Type\\*"{1,20}:\s{0,100}\\*"{1,20}({alert_name}[^\\"]{1,2000})""",
    """({outcome}MessagesBlocked)""",
    """"SourceSystem"{1,20}:"{1,20}({log_source}[^"]{1,2000})"""
  ]
  DupFields = [ "recipient->user_email" ]
}
```