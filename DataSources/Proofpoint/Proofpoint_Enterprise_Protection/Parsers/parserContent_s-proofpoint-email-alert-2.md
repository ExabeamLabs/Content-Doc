#### Parser Content
```Java
{
Name = s-proofpoint-email-alert-2
  Conditions = [ """CEF:""", """destinationServiceName=Proofpoint""", """cat=security-alert""", """"threat""" ]
  Fields = ${PPParserTemplates.s-proofpoint-email-in-1.Fields}[
    """"sha256"{1,20}:"{1,20}({sha256}[^"]+)"{1,20}
s-proofpoint-email-in-1 = {
  Vendor = Proofpoint
  Product = Proofpoint TAP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """threatTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """messageTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """spamScore":\s{0,100}({spam_score}\d{1,100})""",
    """phishScore":\s{0,100}({phishing_score}\d{1,100})""",
    """(,|")malwareScore":\s{0,100}({malware_score}\d{1,100})""",
    """messageSize":\s{0,100}({bytes}\d{1,100})""",
    """classification":\s{0,100}"({alert_type}[^",]+?)\s{0,100}(,|")""",
    """"threatsInfoMap":\s{0,100}\[\{"[^}\]]+?"classification":\s{0,100}"({alert_type}[^"]+)""",
    """"threatsInfoMap":\s{0,100}\[\{"[^}\]]+?"threatType":\s{0,100}"({alert_type}[^"]+)""",
    """subject":\s{0,100}"(\{\\|({subject}[^",]+?))\s{0,100}(,|")""",
    """suser=({sender}[^"\s,@]+@({external_domain}[^"\s,@]+))""",
    """duser=({recipient}[^"\s,@]+@[^"\s,@]+)""", 
    """sender":\s{0,100}"({sender}[^"\s,@]+@({external_domain}[^"\s,@]+))""",
    """recipient":\s{0,100}\[?"({recipients}[^",;]+@[^",;]+[^"]*)""",
    """recipient":\s{0,100}\[?"({recipient}[^",;]+@({external_domain_recipient}[^",;]+))""",
    """GUID":\s{0,100}"({alert_id}[^",]+?)\s{0,100}(,|")""",
    """senderIP":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """url":\s{0,100}"({alert_name}[^",]+?)\s{0,100}(,|")""",
    """proto=({alert_name}[^=]+?)\s\w+=""",
    """\scs1=Policy \[id: [^\]]*? ; name: ({alert_name}[^\]]+?) ; category: ({category}[^\]]+?)]""",
    """threat":\s{0,100}"\s{0,100}({alert_name}[^",]+?)\s{0,100}(,|")""",
    """,\s{0,100}"filename":\s{0,100}"(?!text(\.txt|\.html|-calendar))\s{0,100}({attachments}({attachment}[^",;]+)[^"]*?)",\s{0,100}"\w+":""",
    ""","fromArray":"({outcome}[^\]]+?)","\w+":""",
    """eventType":\s{0,100}"({outcome}[^",]+?)\s{0,100}(,|")""",
    """"messageID":\s{0,100}"<?({message_id}[^>"]+)""",
    """src-account-name":"({account_name}[^"]+)"""
  ]

```