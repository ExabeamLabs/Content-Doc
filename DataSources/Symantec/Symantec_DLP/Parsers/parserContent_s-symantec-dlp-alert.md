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
      """\d\d:\d\d:\d\d\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}CEF:""",
      """\|Symantec\|DLP\|[^|]{0,2000}\|({alert_type}[^|]{1,2000})\|""",
      """\|Symantec\|DLP\|[^|]{0,2000}\|({alert_name}[^|]{1,2000})\|""",
      """\sRULES=({alert_name}.+?)\s{0,100}(\w+=|$)""",
      """\|BLOCKED=(?:N\/A|None|({outcome}.+?))\s{1,100}(\w+=|$)"""
      """\sENDPOINT_MACHINE=(N\/A|({dest_host}[\w.\-]{1,2000}))\s{1,100}(\w+=|$)""",
      """\sFILE_NAME=(?:N\/A|({file_name}.+?))\s{1,100}(\w+=|$)""",
      """\sINCIDENT_ID=({alert_id}\d{1,100})""",
      """\sPROTOCOL=({protocol}.+?)\s{1,100}(\w+=|$)""",
      """\sSENDER=({sender}[^@",]{1,2000}?@[^"\.,]{1,2000}?\.[^",\s]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]{1,2000}@[\w.])({recipients}.+?)\s{1,100}(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]{1,2000}@[\w.])({external_address}[^,\s]{1,2000})""",
      """\sRECIPIENTS=[^@]{1,2000}@({external_domain}[^,@\s]{1,2000})""",
      """\sSEVERITY=({alert_severity}\d{1,100}:\w+)\s{1,100}""",
      """\sSUBJECT=(?:N\/A|({subject}.+?))\s{1,100}(\w+=|$)""",
      """\sUSER=(N\/A|(({domain}[^\\=]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+=|$))""",
      """\sDATAOWNER_NAME=(N\/A|(({domain}[^\\=]{1,2000})\\+)?({user}.+?)\s{1,100}(\w+=|$))""",
      """\sINCIDENT_SNAPSHOT=\w+:\/+[^\s]{0,2000}?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\||")""",
      """\sENDPOINT_DEVICE_ID=(N\/A|({device_id}.+?))\s{0,100}(\w+=|$)""",
      """C:\\Users\\({user}[^\\\s]{1,2000})""",
    ]
    DupFields = [ "external_address->recipient", "sender->user_email", "recipients->target", "subject->additional_info" ]
  }
```