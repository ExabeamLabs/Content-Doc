#### Parser Content
```Java
{
Name = s-symantec-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """|Symantec|DLP|""", """|BLOCKED=""", """INCIDENT_SNAPSHOT=""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]+)\s{1,100}CEF:""",
      """\|Symantec\|DLP\|[^|]*\|({alert_type}[^|]+)\|""",
      """\|Symantec\|DLP\|[^|]*\|({alert_name}[^|]+)\|""",
      """\sRULES=({alert_name}.+?)\s{0,100}(\w+=|$)""",
      """\|BLOCKED=(?:N\/A|None|({outcome}.+?))\s{1,100}(\w+=|$)"""
      """\sENDPOINT_MACHINE=(N\/A|({dest_host}[\w.\-]+))\s{1,100}(\w+=|$)""",
      """\sFILE_NAME=(?:N\/A|({file_name}.+?))\s{1,100}(\w+=|$)""",
      """\sINCIDENT_ID=({alert_id}\d{1,100})""",
      """\sPROTOCOL=({protocol}.+?)\s{1,100}(\w+=|$)""",
      """\sSENDER=({sender}[^@",]+?@[^"\.,]+?\.[^",\s]+?)\s{1,100}(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]+@[\w.])({recipients}.+?)\s{1,100}(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]+@[\w.])({external_address}[^,\s]+)""",
      """\sRECIPIENTS=[^@]+@({external_domain}[^,@\s]+)""",
      """\sSEVERITY=({alert_severity}\d{1,100}:\w+)\s{1,100}""",
      """\sSUBJECT=(?:N\/A|({subject}.+?))\s{1,100}(\w+=|$)""",
      """\sUSER=(N\/A|(({domain}[^\\=]+)\\+)?({user}.+?)\s{1,100}(\w+=|$))""",
      """\sDATAOWNER_NAME=(N\/A|(({domain}[^\\=]+)\\+)?({user}.+?)\s{1,100}(\w+=|$))""",
      """\sINCIDENT_SNAPSHOT=\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\||")""",
      """\sENDPOINT_DEVICE_ID=(N\/A|({device_id}.+?))\s{0,100}(\w+=|$)""",
      """C:\\Users\\({user}[^\\\s]+)""",
    ]
    DupFields = [ "external_address->recipient", "sender->user_email", "recipients->target", "subject->additional_info" ]
  }
```