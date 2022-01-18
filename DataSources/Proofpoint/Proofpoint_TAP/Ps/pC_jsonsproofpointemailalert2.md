#### Parser Content
```Java
{
Name = json-s-proofpoint-email-alert-2
  Conditions = [ """"threatStatus":"""", """"classification":"""", """"threat":""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"threat":\s{0,100}"({malware_url}[^"]{1,2000})""",
    """"threatUrl":\s{0,100}"({threat_url}[^"]{1,2000}?)"""",
    """threatStatus":"({status}[^"]{1,2000})"""",
    """\Woutcome=({outcome}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """"classification":"({alert_name}[^"]{1,2000})""",
    """"threatType":"({alert_type}[^"]{1,2000})""",
  ]
  DupFields = [ "attachment->file_name", "sender->external_address", "recipient->user_email" ]


s-proofpoint-email-in-1 = {
  Vendor = Proofpoint
  Product = Proofpoint TAP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """threatTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """messageTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """spamScore":\s{0,100}({spam_score}\d{1,100})""",
    """phishScore":\s{0,100}({phishing_score}\d{1,100})""",
    """(,|")malwareScore":\s{0,100}({malware_score}\d{1,100})""",
    """messageSize":\s{0,100}({bytes}\d{1,100})""",
    """classification":\s{0,100}"({alert_type}[^",]{1,2000}?)\s{0,100}(,|")""",
    """"threatsInfoMap":\s{0,100}\[\{"[^}\]]{1,2000}?"classification":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """"threatsInfoMap":\s{0,100}\[\{"[^}\]]{1,2000}?"threatType":\s{0,100}"({alert_type}[^"]{1,2000})""",
    """subject":\s{0,100}"(\{\\|({subject}[^",]{1,2000}?))\s{0,100}(,|")""",
    """suser=({sender}[^"\s,@]{1,2000}@({external_domain}[^"\s,@]{1,2000}))""",
    """duser=({recipient}[^"\s,@]{1,2000}@[^"\s,@]{1,2000})""", 
    """sender":\s{0,100}"({sender}[^"\s,@]{1,2000}@({external_domain}[^"\s,@]{1,2000}))""",
    """recipient":\s{0,100}\[?"({recipients}[^",;]{1,2000}@[^",;]{1,2000}[^"]{0,2000})""",
    """recipient":\s{0,100}\[?"({recipient}[^",;]{1,2000}@({external_domain_recipient}[^",;]{1,2000}))""",
    """GUID":\s{0,100}"({alert_id}[^",]{1,2000}?)\s{0,100}(,|")""",
    """senderIP":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """url":\s{0,100}"({alert_name}[^",]{1,2000}?)\s{0,100}(,|")""",
    """proto=({alert_name}[^=]{1,2000}?)\s\w+=""",
    """\scs1=Policy \[id: [^\]]{0,2000}? ; name: ({alert_name}[^\]]{1,2000}?) ; category: ({category}[^\]]{1,2000}?)]""",
    """threat":\s{0,100}"\s{0,100}({alert_name}[^",]{1,2000}?)\s{0,100}(,|")""",
    """,\s{0,100}"filename":\s{0,100}"(?!text(\.txt|\.html|-calendar))\s{0,100}({attachments}({attachment}[^",;]{1,2000})[^"]{0,2000}?)",\s{0,100}"\w+":""",
    ""","fromArray":"({outcome}[^\]]{1,2000}?)","\w+":""",
    """eventType":\s{0,100}"({outcome}[^",]{1,2000}?)\s{0,100}(,|")""",
    """"messageID":\s{0,100}"<?({message_id}[^>"]{1,2000})""",
    """src-account-name":"({account_name}[^"]{1,2000})"""
  ]
  DupFields = [ "attachment->file_name", "sender->external_address" 
}
```