#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-2
  Conditions = [ """CEF:""", """destinationServiceName=Proofpoint""", """cat=security-alert""", """"threat":""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"threat":\s*"({malware_url}[^"]+)""",
    """proto=({alert_name}.+?)\s\w+=""",
    """\Woutcome=({outcome}.+?)(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "attachment->file_name", "sender->external_address", "recipient->user_email" ]

}
s-proofpoint-email-in-1 = {
  Vendor = Proofpoint TAP
  Product = Proofpoint TAP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """threatTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """spamScore":\s*({spam_score}\d+)""",
    """phishScore":\s*({phishing_score}\d+)""",
    """(,|")malwareScore":\s*({malware_score}\d+)""",
    """messageSize":\s*({bytes}\d+)""",
    """classification":\s*"({alert_type}[^",]+?)\s*(,|")""",
    """"threatsInfoMap":\s*\[\{".+?"classification":\s*"({alert_type}[^"]+)""",
    """"threatsInfoMap":\s*\[\{".+?"threatType":\s*"({alert_type}[^"]+)""",
    """subject":\s*"({subject}[^",]+?)\s*(,|")""",
    """sender":\s*"({sender}[^"\s,@]+@({external_domain}[^"\s,@]+))""",
    """recipient":\s*\[?"({recipients}[^",;]+@[^",;]+[^"]*)""",
    """recipient":\s*\[?"({recipient}[^",;]+@[^",;]+)""",
    """GUID":\s*"({alert_id}[^",]+?)\s*(,|")""",
    """senderIP":\s*"({src_ip}[a-fA-F\d.:]+)""",
    """url":\s*"({alert_name}[^",]+?)\s*(,|")""",
    """\scs1=Policy \[id: .*? ; name: ({alert_name}.*?) ; category: ({category}.*?)]""",
    """threat":\s*"\s*({alert_name}[^",]+?)\s*(,|")""",
    """,\s*"filename":\s*"(?!text(\.txt|\.html|-calendar))\s*({attachments}({attachment}[^",;]+)[^"]*?)",\s*"\w+":""",
    ""","fromArray":"({outcome}.*?)","\w+":""",
    """eventType":\s*"({outcome}[^",]+?)\s*(,|")""",
  ]

```