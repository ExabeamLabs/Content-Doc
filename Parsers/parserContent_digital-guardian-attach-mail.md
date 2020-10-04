#### Parser Content
```Java
{
Name = digital-guardian-attach-mail
  Product = Digital Guardian Endpoint Protection
  DataType = "file-upload"
  Conditions = [ """ Agent_Local_Time="""", """ User_Name="""", """ Operation="36"""" ]
  Fields = ${DGParserTemplates.digital-guardian-activity.Fields}[
  ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-alert} {
  Name = s-digitalguardian-dlp-alert-1
  Conditions = [ """Rule_Violation="True"""", """Block_Code="Rule Block"""" ]
  Fields = ${DGParserTemplates.splunk-digitalguardian-dlp-alert.Fields}[
    """[^_]Custom_String_4="({alert_name}[^"]+)""",
    """[^_]Block_Code="({alert_type}[^"]+)""",
    """[^_]Bytes_Read="(?:|({bytes}[^"]+))"""",
  ]
}

${DGParserTemplates.splunk-digitalguardian-file-write} {
  Name = s-digitalguardian-file-write-1
  Conditions = [ """Operation_ID="11"""" , """Agent_UTC_Time=""" ]
}

${DGParserTemplates.splunk-digitalguardian-file-upload} {
  Name = s-digitalguardian-file-upload
  Conditions = [ """Operation_ID="21"""", """Agent_UTC_Time""" ]
}
${DGParserTemplates.splunk-digitalguardian-file-download} {
  Name = s-digitalguardian-file-download
  Conditions = [ """Operation_ID="2"""", """Agent_UTC_Time""" ]
}

${DGParserTemplates.splunk-digitalguardian-dlp-email-out} {
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