#### Parser Content
```Java
{
Name = s-proofpoint-email-in
    Vendor = Proofpoint TAP
    Product = Proofpoint TAP
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """ - ProofpointTAP - """ ]
    Fields = [
      """(delivery|block|click|message)Time="*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
      """exabeam_host=({host}[\w.\-]+)""",
      """- ProofpointTAP -\s+({outcome}[^\s-]+)\s+""",
      """({alert_name}ProofpointTAP)""",
      """\sGUID="*({alert_id}[^\s"]+)""",
      """- ProofpointTAP -\s+CLKBLK\s+-.*?\smessageID=({alert_id}\S+)""",
      """\srecipient="*({recipient}[^\s"]+)""",
      """\ssender="*(null|({sender}[^\s"]+))""",
      """\ssender="*[^@"\s]+@({external_domain}[^\s"]+)""",
      """\ssenderIP="*(null|({src_ip}[a-fA-F\d.:]+))""",
      """\sthreatsInfoMap=\[\{.+?,({alert_type}.+?)\}""",
      """\sthreatsInfoMap="*\[\{.+?,\\"*classification\\"*:\\"*({alert_type}[^\\"]+)""",
      """\sclass=({alert_type}.+?)\s+\w+=""",
      """\ssubject="({subject}[^"]+)""",
      """\smalwareScore="*({malware_score}\d+)""",
      """\sspamScore="*({spam_score}\d+)""",
      """\sphishScore="*({phishing_score}\d+)""",
      """\smessageSize="*({bytes}\d+)"""
    ]
    DupFields = [ 
      "recipient->recipients",
      "sender->external_address",
    ]
  }
```