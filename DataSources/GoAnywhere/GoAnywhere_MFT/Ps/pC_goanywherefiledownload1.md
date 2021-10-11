#### Parser Content
```Java
{
Name = goanywhere-file-download-1
  DataType = "file-download"
  Conditions = [ """GoACHevent_type="Download Successful"""", """GoACHcommand="Download"""", """GoACHremote_ip="""", """GoACHuser_name="""" ]
Fields = ${GoAnywhereParserTemplates.goanywhere-events-2.Fields}[
     """GoACHfile_path="({file_path}[^"]{0,2000}\/({file_name}[^"]{0,2000}))"""",
     """"({activity}Download)""""
  ]
}
goanywhere-events-2 = {
    Vendor = GoAnywhere
    Product = GoAnywhere MFT
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[+-]\d\d:\d\d)\s({dest_host}[\w\-.]{1,2000})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """GoACHremote_ip="({src_ip}[\da-fA-F:\.]{1,100})"""",
      """GoACHlocal_ip="({dest_ip}[\da-fA-F:\.]{1,100})"""",
      """GoACHuser_name="(({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|(admin|666666|guest|({user}[^"]{1,2000})))"""",
      """GoACHevent_type="({event_name}[^"]{1,2000})"""",
    ]
 }
 
}
MvisionParserTemplates = {
 
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