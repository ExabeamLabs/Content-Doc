#### Parser Content
```Java
{
Name = cef-mimecast-dlp-email
  Vendor = Mimecast
  Product = Mimecast
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Mimecast Email Security""", """"Dir":"""", """"Sender":"""", """"Rcpt":"""" ]
  Fields = [
    """"acc":"({host}[^",]+)"""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)\s{1,100}[\w\-.]+\s{1,100}Skyformation""",
    """request=({outcome}[^=]+?)\s{1,100}(\w+=|$)""",
    """suser=(<>|(({user_email}[^\s@]+@[^\s@]+)|({user}[^\s]+)))""",
    """"Rcpt":"({recipients}({recipient}[^\s@;,"]+@[^\s@;,"]+)[^"]*)"""",
    """"Subject":"(|({subject}[^"]+))""""
    """requestMethod=({direction}[^=]*?)\s{1,100}(\w+=|$)""",
    """"Dir":"({direction}[^"]+?)""""
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """"aCode":"(|({alert_id}[^"]+?))"""",
    """"Rcpt":"({external_address}[^\s@;,]+@({external_domain}[^\s@;,"]+))""",
    """Dir=Inbound[^\}]+?"Sender":"(<>|({external_address}[^\s@;,]+@({external_domain}[^\s@;,"]+)))"""", 
    """"Sender":"(<>|({sender}[^"]+))""""
  ]
}
```