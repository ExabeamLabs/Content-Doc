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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,100})?(Z)?""""
      """"detectedSizeBytes":\s{1,100}({bytes}\d{1,100})""""
      """"detectedSizeBytes":\s{1,100}({bytes}[^"]{1,2000}),\s{1,100}""""
      """"msg_normalizedHeader_from_s":"(\[|\s|\\|")*[^\]]{1,2000}?<({sender}[^>]{1,2000}?)>"""
      """"msg_normalizedHeader_from_s":"(\[|\s|\\|")*({sender}[<^,"]{1,2000}?@[^>]{1,2000}?)\\""""
      """"envelope_from_s":"({sender}[^"]{1,2000})""""
      """"envelope_from_s":"[^"]{1,2000}@({external_domain_sender}[^"]{1,2000})""""
      """"smtp\.mailfrom": "({sender}[^"]{1,2000})""""
      """"smtp\.mailfrom": "[^"]{1,2000}@({external_domain_sender}[^"]{1,2000})""""
      """"filter_verified_rcpts_s":"\[\s{0,100}\\*"({recipients}.+?)\\*"\s{0,100}\]","""
      """"filter_verified_rcpts_s": "[^"]{1,2000}@({external_domain_recipient}[^"]{1,2000})""""
      """"filter_verified_rcpts_s":"\[[\s\\"]{0,2000}({recipient}[^,]{1,2000}?@({external_domain_recipient}[^,]{1,2000}?))[\s\\"]{1,2000}"""
      """"msg_header_subject_s":"\[\s{0,100}\\*"({subject}[^\]]{1,2000}?)\\*"\s{0,100}\]",""""
      """"filter_routeDirection_s":"({direction}[^"]{1,2000})""""
      """"filter_disposition_s":"({outcome}[^"]{1,2000})""",
      """"detectedName":\s{0,100}"({attachment}(?!text)[^"]{1,2000})""",
      """"filter_isMsgReinjected_b":[\s"]{0,2000}({is_consolidated}\w+)[\s"]{0,2000}
```