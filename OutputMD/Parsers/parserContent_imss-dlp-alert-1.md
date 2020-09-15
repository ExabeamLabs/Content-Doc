#### Parser Content
```Java
{
Name = imss-dlp-alert-1
  Product = IMSS
  Conditions = [ """メール容量規制""" ]
}

${IMSSParserTemplates.imss-email-alert}{
  Name = imss-security-alert
  Product = IMSS
  Conditions = [ """ウイルス対策ルール""" ]
}

${IMSSParserTemplates.imss-email-alert}{
  Name = imss-security-alert-1
  Product = IMSS
  Conditions = [ """スパムメール対策ルール""" ]
}

${IMSSParserTemplates.imss-email-alert}{
  Name = imss-security-alert-2
  Product = IMSS
  Conditions = [ """SPFレコードチェック""" ]
}

${IMSSParserTemplates.imss-email-alert}{
  Name = imss-security-alert-3
  Product = IMSS
  Conditions = [ """詐称メールフィルタ""" ]
}

{
  Name = leap-app-activity
  Vendor = LEAP
  Product = LEAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyyMMdd:HH.mm.ss"
  Conditions = [ """|LEAPACCESS|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({location}\w+)\|({app_code}({app}LEAPS)[^\|]*)\|LEAPACCESS\|({time}[^\|]+)\|({user}[^\|]+)\|({object}[^\|]+)\|\s*(?:({dest_ip}[a-fA-F\d.:]+)|({dest_host}.+?))\s*\|([^\|]*\|){2}({activity}[^\|]+)\|([^\|]*\|){4}(|({additional_info}.*?))\s+$""",
  ]
}
```