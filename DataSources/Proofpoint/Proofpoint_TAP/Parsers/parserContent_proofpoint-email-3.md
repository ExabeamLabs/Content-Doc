#### Parser Content
```Java
{
Name = proofpoint-email-3
    Vendor = Proofpoint
    Product = Proofpoint TAP
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """routeDirection""", """ProofPointMessageLog_CL""" ]
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w.\-]+)""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,100})?(Z)?""""
      """"detectedSizeBytes":\s{1,100}({bytes}\d{1,100})""""
      """"detectedSizeBytes":\s{1,100}({bytes}[^"]+),\s{1,100}""""
      """"msg_normalizedHeader_from_s":"(\[|\s|\\|")*[^\]]+?<({sender}[^>]+?)>"""
      """"msg_normalizedHeader_from_s":"(\[|\s|\\|")*({sender}[<^,"]+?@[^>]+?)\\""""
      """"envelope_from_s":"({sender}[^"]+)""""
      """"envelope_from_s":"[^"]+@({external_domain_sender}[^"]+)""""
      """"smtp\.mailfrom": "({sender}[^"]+)""""
      """"smtp\.mailfrom": "[^"]+@({external_domain_sender}[^"]+)""""
      """"filter_verified_rcpts_s":"\[\s{0,100}\\*"({recipients}.+?)\\*"\s{0,100}\]","""
      """"filter_verified_rcpts_s": "[^"]+@({external_domain_recipient}[^"]+)""""
      """"filter_verified_rcpts_s":"\[[\s\\"]*({recipient}[^,]+?@({external_domain_recipient}[^,]+?))[\s\\"]+"""
      """"msg_header_subject_s":"\[\s{0,100}\\*"({subject}[^\]]+?)\\*"\s{0,100}\]",""""
      """"filter_routeDirection_s":"({direction}[^"]+)""""
      """"filter_disposition_s":"({outcome}[^"]+)""",
      """"detectedName":\s{0,100}"({attachment}(?!text)[^"]+)""",
      """"filter_isMsgReinjected_b":[\s"]*({is_consolidated}\w+)[\s"]*,"""      
      """"rule":\s{0,100}"({rule_name}[^"]+)""""
    ]
    DupFields = [ "attachment->attachments" ]
  }
```