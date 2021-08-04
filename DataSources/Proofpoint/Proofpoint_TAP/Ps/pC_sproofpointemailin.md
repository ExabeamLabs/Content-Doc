#### Parser Content
```Java
{
Name = s-proofpoint-email-in
    Vendor = Proofpoint
    Product = Proofpoint TAP
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """ - ProofpointTAP - """ ]
    Fields = [
      """(delivery|block|click|message)Time="{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """- ProofpointTAP -\s{1,100}({outcome}[^\s-]{1,2000})\s{1,100}""",
      """({alert_name}ProofpointTAP)""",
      """\sGUID="{0,20}({alert_id}[^\s"]{1,2000})""",
      """- ProofpointTAP -\s{1,100}CLKBLK\s{1,100}-.*?\smessageID=({alert_id}\S+)""",
      """\srecipient="{0,20}({recipient}[^\s"]{1,2000})""",
      """\ssender="{0,20}(null|({sender}[^\s"]{1,2000}))""",
      """\ssender="{0,20}[^@"\s]{1,2000}@({external_domain}[^\s"]{1,2000})""",
      """\ssenderIP="{0,20}(null|({src_ip}[a-fA-F\d.:]{1,2000}))""",
      """\sthreatsInfoMap=\[\{.+?,({alert_type}.+?)\}""",
      """\sthreatsInfoMap="{0,20}\[\{.+?,\\"{0,20}classification\\"{0,20}:\\"{0,20}({alert_type}[^\\"]{1,2000})""",
      """\sclass=({alert_type}.+?)\s{1,100}\w+=""",
      """\ssubject="({subject}[^"]{1,2000})""",
      """\smalwareScore="{0,20}({malware_score}\d{1,100})""",
      """\sspamScore="{0,20}({spam_score}\d{1,100})""",
      """\sphishScore="{0,20}({phishing_score}\d{1,100})""",
      """\smessageSize="{0,20}({bytes}\d{1,100})"""
    ]
    DupFields = [ 
      "recipient->recipients",
      "sender->external_address",
    ]
  }
```