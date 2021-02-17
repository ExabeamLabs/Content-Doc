#### Parser Content
```Java
{
Name = symantec-dlp-cit-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Direct
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ PROTOCOL """, """ POLICY """, """ MATCHES """, """ SEVERITY """, """ BLOCKED """, """ URL """, """ SENDER """, """ RECIPIENTS """, """ FILE_NAME """, """ PARENT_PATH """ ]
    Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}\S+)""",
    """\sFILE_NAME\s(?:N\/A|({attachments}({file_name}.+?)))\sPARENT_PATH\s""",
    """\sSENDER\s\w+:\/\/({domain}[^\<\>\[\]\"\/\\:;\|=,+*\?]+)\/({user}[^\<\>\[\]\"\/\\:;\|=,+*\?]+?)\sRECIPIENTS\s""",
    """\sSENDER\s({sender}[^\s"@,]+@({domain}[^\s"@,]+))\sRECIPIENTS\s""",
    """\sSENDER\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sRECIPIENTS\s""",
    """\sBLOCKED\s(?:N\/A|({outcome}.+?))\sURL\s""",
    """\sSEVERITY\s(?:N\/A|({alert_severity}.*?))\sBLOCKED\s""",
    """\sINCIDENT\s(?:N\/A|({alert_id}\d+?))\sPOLICY\s""",
    """\sPOLICY\s(?:N\/A|({alert_type}.+?))\sMATCHES\s""",
    """\sPROTOCOL\s(?:N\/A|({protocol}.+?))\sINCIDENT\s""",
    """\sRECIPIENTS\s({target}(http:\/\/|https:\/\/).+?)\/.*?\sFILE_NAME\s""",
    """\sRECIPIENTS\s(?:N\/A|https:\/\/.+?|http:\/\/.+?|Unknown|({recipient}[^,]+?))[\s\,]""",
    """\sRECIPIENTS\s(?:N\/A|https:\/\/.+?|http:\/\/.+?|Unknown|({recipients}.+?))\s""",
    """\sRECIPIENTS\s[^@]+@({external_domain}[^\s;,]+)"""
    ]
    DupFields = [ "alert_type->alert_name" , "recipient->external_address" ]
  }
```