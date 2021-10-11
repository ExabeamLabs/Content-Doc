#### Parser Content
```Java
{
Name = s-mvision-dlp-alert-5
  DataType = "dlp-alert"
  Conditions = [ """"threattype":""",""""OUTGOING_FS_REMOVABLE_STORAGE"""",""""PolicyName":""" ,""""threatseverity":""" ]
  Fields = ${MvisionParserTemplates.s-mvision-dlp-alert.Fields}[
    """"DisplayName":\s{1,100}"({additional_info}[^"]{1,2000})"""",
    """"targetprocessname":\s{0,100}"({process_name}[^"]{1,2000})""""
  ]
}
s-mvision-dlp-alert = {
    Vendor = Mvision
    Product = Mvision
    Lms = Splunk
    TimeFormat = "epoch_sec"
    Fields = [
      """"detectedutc":\s{0,100}"({time}\d{1,100})"""",
      """"analyzerhostname":\s{0,100}"({host}[^"]{1,2000})"""",
      """"UserPrincipalName":\s{1,100}"(({user_email}[^@"]{1,2000}@[^."]{1,2000}\.[^"]{1,2000})|(({user}[^@"]{1,2000})@({domain}[^"]{1,2000}))|({=user}[^"]{1,2000}))"""",
      """"SourceUsername":\s{0,100}"(({domain}[^\\"]{1,2000})\\\\)?({user}[^"]{1,2000})"""",
      """"sourceipv4":\s{0,100}"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"targetipv4":\s{0,100}"({dest_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"threattype":\s{0,100}"({alert_name}[^"]{1,2000})"""",
      """"threatseverity":\s{0,100}"({alert_severity}\d{1,100})"""",
      """"threateventid":\s{0,100}({alert_id}\d{1,100})""",
      """"PolicyName":\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """"TotalContentSize":\s{0,100}({bytes}\d{1,100})"""
      """"targetfilename":\s{0,100}"({target}[^"]{1,2000})"""",
      """"threatactiontaken":\s{0,100}"({outcome}[^"]{1,2000})"""",
      """"RuleNames":\s{1,100}"({rule_name}[^"]{1,2000})"""",
    ]
 
```