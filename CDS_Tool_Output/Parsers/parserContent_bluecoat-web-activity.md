#### Parser Content
```Java
{
Name = bluecoat-web-activity
  Vendor = Symantec
  Product = Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","Query_Response":"""", ""","CommandID":"""", """"Response_Code":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"firsttime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"host":"(|({host}[\w\-.]+))"""",
    """"DomainID":"({web_domain}[^"]+)""",
    """"DomainID":".*?({top_domain}[^.\s\/:,]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).+?)"""",
    """"User_Agent":"({user_agent}[^"]+)""",
    """"User_Agent":"(?:-|Mozilla.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """"CommandID":"({method}[^"]+)""",
    """"UserIDSrc":"({user}[^"]+)""",
    """"Response_Code":"({result_code}\d+)""",
    """"Category":"({category}[^"]+)""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"dst_ip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"src_port":({dest_port}\d+)""",
    """"Query_Response":"({action}[^"]+)""",
    """"sig":.+?"name":"({proxy_action}[^"]+)""",
    """"URL":"({uri_path}[^"]+)""",
    """"Bytes_Sent":({bytes_out}\d+)""",
    """"Bytes_Received":({bytes_in}\d+)""",
    """"AppID":"({mime}[^"]+)""",
    """"Destination_Logon_ID":"({app_user}[^"]+)""",
  ]
}
```