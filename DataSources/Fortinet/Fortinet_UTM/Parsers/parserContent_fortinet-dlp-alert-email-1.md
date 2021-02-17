#### Parser Content
```Java
{
Name = fortinet-dlp-alert-email-1
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """from=""", """to=""", """subject=""", """message_name=""", """folder_description=""", """action=""" ]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)\s+({host}[\w\-.]+)""",
    """\Waction=({action}[^;]+)""",
    """\Wfrom=({sender}[^\s@;]+@({external_domain_sender}[^\s@;]+))""",
    """\Wto=({recipients}({recipient}[^\s@;,]+@({external_domain_recipient}[^\s@;,]+))[^;]*)""",
    """\Wsubject=({subject}.*?);\s+(\w+=|$)""",
    """\Wmessage_name=({message_name}.*?);\s+(\w+=|$)""",
    """\Wmessage_size=({bytes}\d+)""",
    """\Wfolder_description=({additional_info}.*?);\s+(\w+=|$)""",
    """\Wfilename=({file_name}[^\.]+\.({file_ext}.*?));\s+(\w+=|$)""",
    """\Wfiletype=({file_type}.*?);\s+(\w+=|$)""",
    """({direction}Outbound|Inbound)""",
    """Sent To:\s*({src_ip}[A-Fa-f:\d.]+)""",
  ]
  DupFields = [ "file_name->attachments" ]
}
```