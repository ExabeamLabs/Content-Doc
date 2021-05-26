#### Parser Content
```Java
{
Name = bluecoat-web-activity
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","Query_Response":"""", ""","CommandID":"""", """"Response_Code":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"host":"(|({host}[\w\-.]{1,2000}))"""",
    """"DomainID":"({web_domain}[^"]{1,2000})""",
    """"DomainID":".*?({top_domain}[^.\s\/:,]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).+?)"""",
    """"User_Agent":"({user_agent}[^"]{1,2000})""",
    """"User_Agent":"(?:-|Mozilla.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """"CommandID":"({method}[^"]{1,2000})""",
    """"UserIDSrc":"({user}[^"]{1,2000})""",
    """"Response_Code":"({result_code}\d{1,100})""",
    """"Category":"({category}[^"]{1,2000})""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"dst_ip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"src_port":({dest_port}\d{1,100})""",
    """"Query_Response":"({action}[^"]{1,2000})""",
    """"sig":.+?"name":"({proxy_action}[^"]{1,2000})""",
    """"URL":"({uri_path}[^"]{1,2000})""",
    """"Bytes_Sent":({bytes_out}\d{1,100})""",
    """"Bytes_Received":({bytes_in}\d{1,100})""",
    """"AppID":"({mime}[^"]{1,2000})""",
    """"Destination_Logon_ID":"({app_user}[^"]{1,2000})""",
  ]
}
```