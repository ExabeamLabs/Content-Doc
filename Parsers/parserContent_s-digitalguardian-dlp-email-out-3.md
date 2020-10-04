#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-email-out-3
  Conditions = [ """Operation="Send Mail"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-email-out} {
  Name = s-digitalguardian-dlp-email-out-4
  Conditions = [ """Operation="Send Mail"""" , """Server_UTC_Timestamp=""" ]
}
```