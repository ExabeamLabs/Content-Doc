#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-email-out-1
  Conditions = [ """Operation_ID="28"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-print-activity} {
  Name = s-digitalguardian-print-activity-1
  Conditions = [ """Operation_ID="22"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-file-write} {
  Name = s-digitalguardian-file-write-2
  Conditions = [ """Operation_ID="7"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-network-connection} {
  Name = s-digitalguardian-network-connection
  Conditions = [ """Operation_ID="4"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-email-out} {
  Name = s-digitalguardian-dlp-email-out-2
  Conditions = [ """Operation="28"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-email-out} {
  Name = s-digitalguardian-dlp-email-out-3
  Conditions = [ """Operation="Send Mail"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-email-out} {
  Name = s-digitalguardian-dlp-email-out-4
  Conditions = [ """Operation="Send Mail"""" , """Server_UTC_Timestamp=""" ]
}
```