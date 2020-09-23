#### Parser Content
```Java
{
Name = cef-o365-dlp-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """|security-threat-detected|""", """cat=security-alert""", """=Office 365""", """act=send-mail""", """"MessageTraceId":"""", """"EventType":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s+({host}[\w\-.]+)\s+Skyformation"""
    """filePath=<*({file_path}.+?)>*\s\w+=""",
    """fname=({file_name}.+?)\s*\w+=""",
    """"Domain":"({domain}[^"]+)""",
    """"Subject":"({subject}.+?)\s*"""",
    """"MessageSize":({bytes}\d+)""",
    """"Direction":"({direction}[^"]+)""",
    """"SenderAddress":"({sender}[^"]+)""",
    """"SenderAddress":"[^@"]+@({external_domain_sender}[^",]+)"""",
    """"RecipientAddress":"({recipient}[^"]+)""",
    """"RecipientAddress":"[^@"]+@({external_domain_recipient}[^",]+)"""",
    """"TransportRule":"({alert_name}[^"]+)""",
    """"EventType":"({alert_type}[^"]+)"""
    	
 ]
   DupFields=["sender->user_email"]
}

{
  Name = cef-o365-dlp-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|security-threat-detected|""", """flexString1=DlpRuleMatch""" , """destinationServiceName=Office 365"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """ext_CreationTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """suser=({user_email}.*?)\s\w+=""", 
    """suid=({user_id}.*?)\s\w+=""", 
    """dpriv=({alert_type}.*?)\s\w+=""",
    """proto=({alert_name}.*?)\s\w+=""",
    """duser=({recipient}.*?)\s\w+=""", 
    """message=({additional_info}.*?)\s\w+=""", 
    """filePath=<*({file_path}.*?)>*\s\w+=""",
    """fname=({file_name}.*?)\s\w+=""",
    """dpid=({alert_id}.*?)\s\w+=""",
    """ext_PolicyDetails_0__Rules_0__Severity=({alert_severity}.*?)\s\w+=""",
  ]
  DupFields = [ "recipient->target" ]
}
```