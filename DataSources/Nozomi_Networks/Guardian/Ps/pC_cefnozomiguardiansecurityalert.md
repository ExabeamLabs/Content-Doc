#### Parser Content
```Java
{
Name = cef-nozomi-guardian-security-alert
    Vendor = Nozomi Networks
    Product = Guardian
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = ["""CEF:""", """|Nozomi Networks|""", """|N2OS|""", """flexString3="""]
    Fields = [
       """\sdvchost=({host}[\w.-]{1,2000})""",
       """\scs1=({alert_severity}[^\s]{1,2000})""",
       """\|Nozomi Networks\|([^\|]{1,2000}\|){2}({alert_type}[^\|]{1,2000})""",
       """\scs3=({alert_id}[^\s]{1,2000})""",
       """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})\s""",
       """\sspt=({src_port}\d{1,2000})""",
       """\sdpt=({dest_port}\d{1,2000})""",
       """\sflexString3=({alert_name}.{1,2000}?)(?=(?:\s|\||,|;)[\w.-]+=)""",
       """\s\WMD5:\s({md5}[^)\s]{1,2000})""",
       """\smsg=({additional_info}.{1,2000}?)(?=(?:\s|\||,|;)[\w.-]+=)""",
       """\sshost=({src_host}[\w.-]{1,2000})""",
       """\sflexString1=({mitre_tech}[^\s]{1,2000})""",
       """\sflexString2=({mitre_tactic}[^\s]{1,2000})""",
       """\sstart=({time}\d{1,2000})""",
       """\sproto=((?i)UNKNOWN|({protocol}[^\s]{1,2000}))""",
       """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
       """\sdhost=({dest_host}[\w.-]{1,2000})""",
       """\Sapp=({app}[^\s]{1,2000})"""
  ]


}
```