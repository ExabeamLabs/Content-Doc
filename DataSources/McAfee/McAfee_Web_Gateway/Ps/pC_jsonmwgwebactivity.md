#### Parser Content
```Java
{
Name = json-mwg-web-activity
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Direct
    IsHVF = true
    DataType = "web-activity"
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """"pxyOutAd":"""", """pxyPort":"""",""""urlLongCat":""",""""amwProbability":"""  ]
    Fields = [
        """"timeStamp":"\[({time}\d{1,100}\/\w+\/\d{4}:\d\d:\d\d:\d\d (\+|\-)\d{4})\]"""",
        """"dstURL":"({full_url}\w+:\/\/[^:\/"]{1,2000}(:({dest_port}\d{1,100}))?({uri_path}\/[^\?"]{0,2000})?({uri_query}\?[^"]{0,2000})?)"""",
        """"urlLongCat":"({categories}({category}[^",]{1,2000})[^"]{0,2000})"""",
        """"connSrc":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """"connDst":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """"urlHost":"(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^"]{1,2000}))"""",
        """"authUser":"(?:\([^\)]{1,2000}\)|({user}[^"]{1,2000}))"""",
        """"blkReason":"({failure_reason}[^"]{1,2000})"""",
        """"authMethod":"({auth_method}[^"]{1,2000})"""",
        """"authStatus":"({authenticated}[^"]{1,2000})"""",
        """FailMsg":"({failure_msg}[^"]{1,2000})"""",
        """"cheStatus":"({proxy_action}[^"]{1,2000})"""",
        """"headUsrAgt":"({user_agent}[^"]{1,2000})"""",
        """"mediaPbly":"({mime}[^"]{1,2000})"""",
        """"respStatus":"({result_code}[^"]{1,2000})"""",
        """"connRunTime":"({conn_duration}[^"]{1,2000})"""",
        """"urlCat":"({category_id}[^"]{1,2000})"""",
        """"connProto":"({protocol}[^"]{1,2000})"""",
        """"pxyPort":"({src_port}\d{1,100})"""",
        """"byteP2C":"({bytes_out}\d{1,100})"""",
        """"byteC2P":"({bytes_in}\d{1,100})"""",
    ]


}
```