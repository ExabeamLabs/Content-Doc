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
        """"timeStamp":"\[({time}\d+\/\w+\/\d{4}:\d\d:\d\d:\d\d (\+|\-)\d{4})\]"""",
        """"dstURL":"({full_url}\w+:\/\/[^:\/"]+(:({dest_port}\d+))?({uri_path}\/[^\?"]*)?({uri_query}\?[^"]*)?)"""",
        """"urlLongCat":"({categories}({category}[^",]+)[^"]*)"""",
        """"urlDom":"({top_domain}[^"]+)"""",
        """"connSrc":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """"connDst":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """"urlHost":"(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^"]+))"""",
        """"authUser":"(?:\([^\)]+\)|({user}[^"]+))"""",
        """"blkReason":"({failure_reason}[^"]+)"""",
        """"authMethod":"({auth_method}[^"]+)"""",
        """"authStatus":"({authenticated}[^"]+)"""",
        """FailMsg":"({failure_msg}[^"]+)"""",
        """"cheStatus":"({proxy_action}[^"]+)"""",
        """"headUsrAgt":"({user_agent}[^"]+)"""",
        """"headUsrAgt":"(?:|({browser}[^"]+))"""",
        """"headUsrAgt":"({browser}[\w\-]+)\/[\d\._]+""",
        """"headUsrAgt":"({browser}[^\/";]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
        """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
        """Mozilla\/.+\((?:BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+Gecko\/\d+\s+({browser}\w+)""",
        """"mediaPbly":"({mime}[^"]+)"""",
        """"respStatus":"({result_code}[^"]+)"""",
        """"connRunTime":"({conn_duration}[^"]+)"""",
        """"urlCat":"({category_id}[^"]+)"""",
        """"connProto":"({protocol}[^"]+)"""",
        """"pxyPort":"({src_port}\d+)"""",
        """"byteP2C":"({bytes_out}\d+)"""",
        """"byteC2P":"({bytes_in}\d+)"""",
    ]
}

  {
    Name = s-mcafee-security-alert
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """|Executable Fingerprint""", """|4|""" ]
    Fields = [
      """^[^|]*\|({time}\d+\-\d+\-\d+ \d+:\d+:\d+)""",
      """^([^|]*\|){3}({src_host}[^|]+)\|""",
      """^([^|]*\|){4}({src_ip}[a-fA-F0-9.:]+)""",
      """^([^|]*\|){5}(({domain}.+?)\\)?({user}[^\\|]+)\|""",
      """^([^|]*\|){6}({malware_url}.+?\\+({malware_file_name}[^\\|]+))\|""",
      """^([^|]*\|){11}({alert_type}[^|]+)\|""",
      """^([^|]*\|){12}({alert_type_id}\d+)""",
      """^([^|]*\|){13}({alert_name}[^|]+)\|""",
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```