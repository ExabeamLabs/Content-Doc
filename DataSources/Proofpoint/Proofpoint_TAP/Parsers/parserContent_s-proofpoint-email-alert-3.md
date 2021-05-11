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
    """exabeam_host=({host}[\w.\-]+)""",
    """threatTime\\*"{1,20}:\s{0,100}\\*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """spamScore_d"{1,20}:\s{0,100}"{1,20}({spam_score}\d{1,100})""",
    """phishScore_d"{1,20}:\s{0,100}"{1,20}({phishing_score}\d{1,100})""",
    """"malwareScore_d"{1,20}:\s{0,100}"{1,20}({malware_score}\d{1,100})""",
    """classification\\*"{1,20}:\s{0,100}\\*"{1,20}({alert_type}[^",]+?)\\*\s{0,100}"""",
    """"subject_s"{1,20}:\s{0,100}"{1,20}({subject}[^",]+?)\s{0,100}"""",
    """"fromAddress_s"{1,20}:\s{0,100}"{1,20}\[(\\r|\\n)*\s{0,100}\\"{1,20}({sender}[^",;]+@[^",;]+[^"]*)\\""",
    """"recipient_s"{1,20}:\s{0,100}"{1,20}\[(\\r|\\n)*\s{0,100}\\"{1,20}({recipient}[^",;]+@[^",;]+[^"]*)\\""",
    """GUID_s"{1,20}:\s{0,100}"{1,20}({alert_id}[^",]+?)\s{0,100}"""",
    """senderIP_s"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"filename\\*"{1,20}:\s{0,100}\\*"{1,20}({attachments}(?!text)[^"\\]+)""",
    """"md5\\*"{1,20}:\s{0,100}\\*"{1,20}({md5}[^\\"]+)""",
    """"sha256\\*"{1,20}:\s{0,100}\\*"{1,20}({sha256}[^\\"]+)""",
    """"threatStatus\\*"{1,20}:\s{0,100}\\*"{1,20}({status}[^\\"]+)""",
    """"threatID\\*"{1,20}:\s{0,100}\\*"{1,20}({threat_id}[^\\"]+)""",
    """"threatUrl\\*"{1,20}:\s{0,100}\\*"{1,20}({malware_url}[^\\"]+)""",
    """"messageSize_d\\*"{1,20}:\s{0,100}\\*"{1,20}({bytes}\d{1,100})""",
    """"oContentType\\*"{1,20}:\s{0,100}\\*"{1,20}({mime}[^\\"]+)""",
    """"QID_s\\*"{1,20}:\s{0,100}\\*"{1,20}({query_id}[^\\"]+)""",
    """"Type\\*"{1,20}:\s{0,100}\\*"{1,20}({alert_name}[^\\"]+)""",
    """({outcome}MessagesBlocked)""",
    """"SourceSystem"{1,20}:"{1,20}({log_source}[^"]+)"""
  ]
  DupFields = [ "recipient->user_email" ]
}
```