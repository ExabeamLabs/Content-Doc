#### Parser Content
```Java
{
Name = nas-share-access-1
  Vendor = Synology NAS
  Product = Synology NAS
  Lms = Direct
  DataType = "share-access"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """ Connection """, """accessed the shared folder""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s+({host}\S+)""",
    """exabeam_indexTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """Connection\s+(({domain}[^\\]+)\\)?({user}[^\\,]+),""",
    """({protocol}\S+)\s+client\s+\[(({domain}[^\\]+)\\)?({user}[^\\]+?)\]""",
    """from .*?IP:({src_ip}[a-fA-F\d.:]+)""",
    """accessed the shared ({file_type}folder) \[({share_name}.+?)\]"""
  ]
}

{
  Name = messagelabs-email-in
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = ["""emailInfo""","""HELOString""",""""isOutbound":false"""]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}[\w.\-]+)""",
    """"mailProcessingStartTime"+:({time}\d+)""",
    """"headerFrom":"({sender}[^"@]+@({external_domain}[^@"]+))",""",
    """"subject":"({subject}[^"]+)",""",
    """"messageSize":({bytes}\d+)""",
    """"messageId":"({alert_id}[^"]+)",""",
    """"headerTo":\[({recipients}[^\]]+)\],""",
    """"headerTo":\["({recipient}[^"]+)"""",
    """"isOutbound":({direction}[^,]+),""",
    """"senderIp":"({src_ip}[a-fA-F\d.:]+)"""
  ]
  DupFields = [ "recipient->email_user", "recipient->user_email", "sender->external_address" ]
}
```