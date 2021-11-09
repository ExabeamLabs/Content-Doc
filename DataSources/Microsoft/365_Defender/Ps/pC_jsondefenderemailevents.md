#### Parser Content
```Java
{
Name = json-defender-email-events
  Vendor = Microsoft
  Product = 365 Defender
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:SSZ"
  Conditions = [ """"category": "AdvancedHunting-EmailEvents"""", """"operationName": "Publish"""", """"EmailDirection":""" ]
  Fields = [
    """"Timestamp":\s{0,10}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"RecipientEmailAddress":\s{0,10}"({recipient}[^"@\s]{1,2000}@[^"@\s]{1,2000}?)"""",
    """"SenderFromAddress":\s{0,10}"({sender}[^"@\s]{1,2000}@[^"@\s]{1,2000}?)"""",
    """"SenderMailFromAddress":\s{0,10}"({sender}[^"@\s]{1,2000}@[^"@\s]{1,2000}?)"""",
    """"SenderFromDomain":\s{0,10}"({external_domain_sender}[^"]{1,2000}?)"""",
    """"EmailDirection":\s{0,10}"((?i)unknown|({direction}[^"]{1,2000}?))"""",
    """"Subject":\s{0,10}"({subject}[^\n]{1,2000}?)"(,\s{0,10}"\w{1,100}":|\s{0,10}\})""", 
    """"SenderIPv4":\s{0,10}"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"AttachmentCount":\s{0,10}({num_attachments}\d{1,10})""",
    """"NetworkMessageId":\s{0,10}"({message_id}[^"]{1,2000}?)"""",
    """"DeliveryAction":\s{0,10}"({outcome}[^"]{1,2000}?)"""",
    """({file_verdict}Malicious Payload)"""
    ]
}
```