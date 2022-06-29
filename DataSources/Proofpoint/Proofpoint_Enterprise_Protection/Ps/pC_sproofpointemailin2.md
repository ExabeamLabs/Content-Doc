#### Parser Content
```Java
{
Name = s-proofpoint-email-in-2
  Conditions = [ """Proofpoint""", """"threatsInfoMap\":""", """"threatTime\":""", """"threat\":""", """"default_inbound\"""" ]
  Fields = ${PPParserTemplates.proofpoint-email.Fields}[
    """"spamScore\\":\s{0,100}({spam_score}\d{1,20})""",
    """"malwareScore\\":\s{0,100}({malware_score}\d{1,20})""",
    """"phishScore\\":\s{0,100}({phishing_score}\d{1,20})""",
    """"threatStatus\\":\s{0,100}\\"{1,20}({additional_info}[^"\\]{1,2000})"""
  ]
  DupFields = [ "sender->external_address", "recipient->user_email"]

proofpoint-email = {
  Vendor = Proofpoint
  Product = Proofpoint Enterprise Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wsuser=({sender}.+?)\s{0,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdhost=({dest_host}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipients}.+?)\s{0,100}(\w+=|$)""",
    """\Wduser=({recipient}[^@]{1,2000}@[^\s,]{1,2000})""",
    """\Wcn1=({bytes}\d{1,100})""",
    """\Wcs5=({attachments}.+?)\s{0,100}(\w+=|$)""",
    """\Wcs5="?({attachment}[^,"]{1,2000}?)("|,|\s{0,100}(\w+=|$))""",
    """\Wcs6=({subject}.+?)\s{0,100}(\w+=|$)""",
    """\Wdproc=({message_id}.+?)\s{0,100}(\w+=|$)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})"""
  ]
  DupFields = [ "attachment->file_name", "alert_name->alert_type" 
}
```