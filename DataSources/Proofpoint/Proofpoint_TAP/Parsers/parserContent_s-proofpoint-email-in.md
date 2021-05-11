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
      """exabeam_host=({host}[\w.\-]+)""",
      """- ProofpointTAP -\s{1,100}({outcome}[^\s-]+)\s{1,100}""",
      """({alert_name}ProofpointTAP)""",
      """\sGUID="{0,20}({alert_id}[^\s"]+)""",
      """- ProofpointTAP -\s{1,100}CLKBLK\s{1,100}-.*?\smessageID=({alert_id}\S+)""",
      """\srecipient="{0,20}({recipient}[^\s"]+)""",
      """\ssender="{0,20}(null|({sender}[^\s"]+))""",
      """\ssender="{0,20}[^@"\s]+@({external_domain}[^\s"]+)""",
      """\ssenderIP="{0,20}(null|({src_ip}[a-fA-F\d.:]+))""",
      """\sthreatsInfoMap=\[\{.+?,({alert_type}.+?)\}""",
      """\sthreatsInfoMap="{0,20}\[\{.+?,\\"{0,20}classification\\"{0,20}:\\"{0,20}({alert_type}[^\\"]+)""",
      """\sclass=({alert_type}.+?)\s{1,100}\w+=""",
      """\ssubject="({subject}[^"]+)""",
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