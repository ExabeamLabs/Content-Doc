#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-3
  Vendor = Proofpoint TAP
  Product = Proofpoint TAP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ProofPointTAPMessagesBlocked""", """sender_s":""", """"senderIP_s":""", """recipient_s":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """threatTime\\*"+:\s*\\*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """spamScore_d"+:\s*"+({spam_score}\d+)""",
    """phishScore_d"+:\s*"+({phishing_score}\d+)""",
    """"malwareScore_d"+:\s*"+({malware_score}\d+)""",
    """classification\\*"+:\s*\\*"+({alert_type}[^",]+?)\\*\s*"""",
    """"subject_s"+:\s*"+({subject}[^",]+?)\s*"""",
    """"fromAddress_s"+:\s*"+\[(\\r|\\n)*\s*\\"+({sender}[^",;]+@[^",;]+[^"]*)\\""",
    """"recipient_s"+:\s*"+\[(\\r|\\n)*\s*\\"+({recipients}[^",;]+@[^",;]+[^"]*)\\""",
    """GUID_s"+:\s*"+({alert_id}[^",]+?)\s*"""",
    """senderIP_s"+:\s*"+({src_ip}[a-fA-F\d.:]+)""",
    """"filename\\*"+:\s*\\*"+({attachments}(?!text)[^"\\]+)""",
    """"md5\\*"+:\s*\\*"+({md5}[^\\"]+)""",
    """"sha256\\*"+:\s*\\*"+({sha256}[^\\"]+)""",
    """"threatStatus\\*"+:\s*\\*"+({status}[^\\"]+)""",
    """"threatID\\*"+:\s*\\*"+({threat_id}[^\\"]+)""",
    """"threatUrl\\*"+:\s*\\*"+({malware_url}[^\\"]+)""",
    """"messageSize_d\\*"+:\s*\\*"+({bytes}\d+)""",
    """"oContentType\\*"+:\s*\\*"+({mime}[^\\"]+)""",
    """"QID_s\\*"+:\s*\\*"+({query_id}[^\\"]+)""",
    """"Type\\*"+:\s*\\*"+({alert_name}[^\\"]+)""",
    """({outcome}MessagesBlocked)""",
    """"SourceSystem"+:"+({log_source}[^"]+)"""
  ]
  DupFields = [ "recipient->user_email" ]
}
```