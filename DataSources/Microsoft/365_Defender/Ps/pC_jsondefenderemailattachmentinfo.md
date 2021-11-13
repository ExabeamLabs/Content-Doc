#### Parser Content
```Java
{
Name = json-defender-email-attachment-info
  Vendor = Microsoft
  Product = 365 Defender
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:SSZ"
  Conditions = [ """"category": "AdvancedHunting-EmailAttachmentInfo"""", """"operationName": "Publish"""", """"FileName":""", """"FileType":""" ]
  Fields = [
    """"Timestamp":\s{0,10}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"RecipientEmailAddress":\s{0,10}"({recipient}[^"@\s]{1,2000}@[^"@\s]{1,2000}?)"""",
    """"SenderFromAddress":\s{0,10}"({sender}[^"@\s]{1,2000}@[^"@\s]{1,2000}?)"""",
    """"category":\s{0,10}"({category}[^"]{1,2000}?)"""",
    """"FileName":\s{0,10}"({file_name}[^"\.]{1,2000}?(\.({file_ext}[^"]{1,2000}?))?)"""",
    """"FileType":\s{0,10}"({file_type}[^"]{1,2000}?)"""",
    """"NetworkMessageId":\s{0,10}"({message_id}[^"]{1,2000}?)""""
    ]
  DupFields = [ "file_name->attachment"]


}
```