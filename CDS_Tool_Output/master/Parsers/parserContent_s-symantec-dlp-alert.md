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
      """\d\d:\d\d:\d\d\s+({host}[\w.\-]+)\s+CEF:""",
      """\|Symantec\|DLP\|[^|]*\|({alert_type}[^|]+)\|""",
      """\|Symantec\|DLP\|[^|]*\|({alert_name}[^|]+)\|""",
      """\sRULES=({alert_name}.+?)\s*(\w+=|$)""",
      """\|BLOCKED=(?:N\/A|None|({outcome}.+?))\s+(\w+=|$)"""
      """\sENDPOINT_MACHINE=(N\/A|({dest_host}[\w.\-]+))\s+(\w+=|$)""",
      """\sFILE_NAME=(?:N\/A|({file_name}.+?))\s+(\w+=|$)""",
      """\sINCIDENT_ID=({alert_id}\d+)""",
      """\sPROTOCOL=({protocol}.+?)\s+(\w+=|$)""",
      """\sSENDER=({sender}[^@",]+?@[^"\.,]+?\.[^",\s]+?)\s+(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]+@[\w.])({recipients}.+?)\s+(\w+=|$)""",
      """\sRECIPIENTS=(?=[\w.]+@[\w.])({external_address}[^,\s]+)""",
      """\sRECIPIENTS=[^@]+@({external_domain}[^,@\s]+)""",
      """\sSEVERITY=({alert_severity}\d+:\w+)\s+""",
      """\sSUBJECT=(?:N\/A|({subject}.+?))\s+(\w+=|$)""",
      """\sUSER=(N\/A|(({domain}[^\\=]+)\\+)?({user}.+?)\s+(\w+=|$))""",
      """\sDATAOWNER_NAME=(N\/A|(({domain}[^\\=]+)\\+)?({user}.+?)\s+(\w+=|$))""",
      """\sINCIDENT_SNAPSHOT=\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\||")""",
      """\sENDPOINT_DEVICE_ID=(N\/A|({device_id}.+?))\s*(\w+=|$)""",
      """C:\\Users\\({user}[^\\\s]+)""",
    ]
    DupFields = [ "external_address->recipient", "sender->user_email", "recipients->target", "subject->additional_info" ]
  }
```