#### Parser Content
```Java
{
Name = checkpoint-dlp-email-alert
  DataType = "dlp-email-alert"
  IsHVF = false
  Conditions = [ """product:"VPN-1 & FireWall-1"""", """email_recipients_num:"""", """from:"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """\Wemail_recipients_num:"({num_recipients}\d+)""",
    """\Wfrom:"({sender}[^"\s]+)""",
  ]
}
```