#### Parser Content
```Java
{
Name = cef-mimecast-email-alert
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """dproc=TTP URL Logs""", """destinationServiceName=Mimecast Email Security""", """"userEmailAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s*[^\s]+\s*Skyformation""",
    """"date":"({time}[^"]+)""",
    """"userEmailAddress":"({user_email}[^\s@"]+@[^\s@"]+)""",
    """"action":"({action}[^"]+)""",
    """"category":"(Unknown|({category}[^"]+))""",
    """"+fromUserEmailAddress"+:"+({sender}[^"]+)""",
    """"+url"+:"+({url}[^"]+)""",
    """"+ttpDefinition"+:"+({service}[^"]+)""",
    """"+subject"+:"+\s*({subject}.+?)\s*"+""",
    """"+route"+:"+({direction}[^"]+)""",
    """"+scanResult"+:"+({url_verdict}[^"]+)""",
    """"+scanResult"+:"+(clean|({failure_reason}[^"]+))"""
    ]
    DupFields = ["user_email->recipient","user_email->email_user"]
}
```